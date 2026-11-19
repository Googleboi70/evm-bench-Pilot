#!/usr/bin/env python3
"""evmbench-pilot scaffold v0: a minimal, read-only smart-contract audit agent.

* Talks to any OpenAI-compatible /chat/completions endpoint (Gemini, OpenRouter, Groq,
  DeepSeek, a local mock server, ...). It uses a plain-JSON action protocol, so it
  works even if the model has no native tool calling.
* The agent can only list/read/grep a *copy* of the task folder, placed in a randomly
  named temp directory. It never sees "vuln", "fixed" or any grader files.
* Each run gets a random ID. runs/<id>/findings.json is what you grade (blinded). The
  run -> task/variant/model mapping and the token counts go to runs/_mapping.csv.
  Do not open that file until grading is finished.

Usage:
    python scaffold/agent.py --task tasks/<name>/vuln --variant v0 --out runs/
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import find_dotenv, load_dotenv

from tools import ToolError, Workspace

SCAFFOLD_VERSION = "0.1.0"
HERE = Path(__file__).resolve().parent
PROMPT_DIR = HERE / "prompts"

# Which tools each variant may use. v1 (PoC verification) will extend this.
VARIANT_TOOLS = {"v0": ["list_files", "read_file", "grep", "finish"]}

# Files/dirs that would leak the answer if they were inside the agent's workspace.
LEAK_FILES = {"Solution.t.sol", "ground_truth.md"}
LEAK_DIRS = {"grader", "fixed", "vuln"}
IGNORE_ON_COPY = shutil.ignore_patterns(
    ".git", "out", "cache", "broadcast", "node_modules", ".env", ".env.*", "__pycache__", "*.pyc"
)

THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
MAPPING_FIELDS = [
    "run_id", "started_utc", "task", "variant", "model", "base_url_host", "steps",
    "tool_calls", "parse_errors", "tokens_in", "tokens_out", "usage_estimated_calls",
    "wall_seconds", "finish_reason", "report_status", "findings_count", "params",
]


# --------------------------------------------------------------------------- LLM
class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url, model, api_key, temperature=0.2, max_output_tokens=4096,
                 timeout=120, min_interval=0.0, max_retries=6):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.timeout = timeout
        self.min_interval = min_interval
        self.max_retries = max_retries
        self._last_call = 0.0

    @staticmethod
    def _retry_delay(resp, attempt):
        header = resp.headers.get("Retry-After")
        if header:
            try:
                return min(300.0, float(header))
            except ValueError:
                pass
        m = re.search(r'retry[_ ]?delay"?\s*[:=]\s*"?(\d+(?:\.\d+)?)s', resp.text, re.IGNORECASE)
        if m:
            return min(300.0, float(m.group(1)) + 1.0)
        return min(120.0, 5.0 * 2 ** attempt)

    def chat(self, messages):
        """Return (text, prompt_tokens | None, completion_tokens | None)."""
        payload = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if self.max_output_tokens:
            payload["max_tokens"] = self.max_output_tokens
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_err = "unknown error"
        for attempt in range(self.max_retries + 1):
            wait = self.min_interval - (time.time() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()
            delay = min(120.0, 5.0 * 2 ** attempt)
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as e:
                last_err = f"network error: {e.__class__.__name__}"
            else:
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        choice = data["choices"][0]["message"]
                    except (ValueError, KeyError, IndexError, TypeError):
                        last_err = f"unexpected response body: {resp.text[:300]}"
                    else:
                        content = choice.get("content")
                        if isinstance(content, list):  # some providers return content parts
                            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
                        usage = data.get("usage") or {}
                        return (content or ""), usage.get("prompt_tokens"), usage.get("completion_tokens")
                elif resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500:
                    last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    delay = self._retry_delay(resp, attempt)
                else:
                    raise LLMError(f"HTTP {resp.status_code} from {urlparse(self.url).netloc}: {resp.text[:500]}")
            if attempt < self.max_retries:
                print(f"  [retry {attempt + 1}/{self.max_retries} in {delay:.0f}s] {last_err}", file=sys.stderr)
                time.sleep(delay)
        raise LLMError(
            f"giving up after {self.max_retries} retries: {last_err}. "
            "If this is a daily quota, wait for the reset or switch provider."
        )


# ------------------------------------------------------------------------ helpers
def strip_think(text: str) -> str:
    return THINK_RE.sub("", text or "").strip()


def est_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def parse_action(text: str):
    """Extract the first JSON action from a model reply.

    Returns (action, extra_ignored). action is {"tool": str, "args": dict} or None.
    """
    text = strip_think(text)
    decoder = json.JSONDecoder()
    found, i, attempts = [], 0, 0
    while attempts < 60:
        i = text.find("{", i)
        if i == -1:
            break
        attempts += 1
        try:
            obj, end = decoder.raw_decode(text[i:])
        except json.JSONDecodeError:
            i += 1
            continue
        if isinstance(obj, dict) and isinstance(obj.get("tool"), str):
            found.append(obj)
            i += end
        elif isinstance(obj, dict) and "findings" in obj:  # model returned the report directly
            found.append({"tool": "finish", "args": obj})
            i += end
        else:
            i += 1
    if not found:
        return None, False
    first = found[0]
    args = first.get("args")
    if args is None:
        args = {k: v for k, v in first.items() if k != "tool"}
    return {"tool": first["tool"].strip(), "args": args}, len(found) > 1


def validate_findings(args):
    if not isinstance(args, dict):
        raise ValueError("args must be an object with 'summary' and 'findings'")
    findings = args.get("findings")
    if not isinstance(findings, list):
        raise ValueError("'findings' must be a list (use [] if you found nothing exploitable)")
    warnings = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            raise ValueError(f"finding {i} must be an object")
        for key in ("title", "vulnerability_type", "severity", "location", "description"):
            if not str(f.get(key, "")).strip():
                warnings.append(f"finding {i}: missing '{key}'")
    return findings, str(args.get("summary", "")), warnings


def git_commit():
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, timeout=5, cwd=HERE)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def check_task_dir(task: Path):
    if not task.is_dir():
        sys.exit(f"error: task folder not found: {task}")
    leaks = sorted(p.name for p in task.iterdir() if p.is_dir() and p.name in LEAK_DIRS)
    if leaks:
        sys.exit(
            f"error: {task} contains {', '.join(leaks)}. Pass the version folder itself "
            "(e.g. tasks/<name>/vuln), not the task parent; otherwise the agent could see the answer."
        )
    for p in task.rglob("*"):
        if p.is_file() and p.name in LEAK_FILES and "lib" not in p.relative_to(task).parts:
            sys.exit(f"error: {p} would leak the grader to the agent. Keep grader files outside the version folder.")


def append_mapping(out_dir: Path, row: dict):
    path = out_dir / "_mapping.csv"
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=MAPPING_FIELDS, lineterminator="\n")
        if new:
            writer.writeheader()
        writer.writerow(row)


# --------------------------------------------------------------------------- run
def run_once(args, client, system_prompt, prompt_hash, tools_allowed):
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]
    while (out_dir / run_id).exists():
        run_id = uuid.uuid4().hex[:8]
    run_dir = out_dir / run_id
    run_dir.mkdir()

    started = datetime.now(timezone.utc)
    t0 = time.time()
    tmp_root = Path(tempfile.mkdtemp(prefix="audit_"))
    workspace_dir = tmp_root / "workspace"
    shutil.copytree(args.task, workspace_dir, ignore=IGNORE_ON_COPY, symlinks=False)
    ws = Workspace(workspace_dir, max_chars=args.max_tool_chars)

    task_md = ""
    tm = workspace_dir / "TASK.md"
    if tm.is_file():
        task_md = tm.read_text(encoding="utf-8", errors="replace")[:4000].strip()
    if task_md:
        first_user = (
            "Audit the project in the workspace.\n\nTask notes (from TASK.md):\n<<<\n"
            f"{task_md}\n>>>\n\nBegin by listing the files. Reply with one JSON action."
        )
    else:
        first_user = (
            "Audit the project in the workspace. No TASK.md was provided: audit all non-test, "
            "non-dependency contracts.\n\nBegin by listing the files. Reply with one JSON action."
        )

    messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": first_user}]
    transcript = (run_dir / "transcript.jsonl").open("w", encoding="utf-8")

    def log(event: dict):
        event["t"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        transcript.write(json.dumps(event, ensure_ascii=False) + "\n")
        transcript.flush()

    log({"type": "system", "content": system_prompt})
    log({"type": "user", "content": first_user})

    stats = {"tokens_in": 0, "tokens_out": 0, "estimated_calls": 0, "calls": 0}

    def call_model():
        sent = list(messages)
        t_call = time.time()
        text, p_tok, c_tok = client.chat(sent)
        stats["calls"] += 1
        if p_tok is None or c_tok is None:
            stats["estimated_calls"] += 1
            p_tok = est_tokens("".join(m["content"] for m in sent))
            c_tok = est_tokens(text)
        stats["tokens_in"] += int(p_tok)
        stats["tokens_out"] += int(c_tok)
        log({"type": "assistant", "content": text, "prompt_tokens": p_tok,
             "completion_tokens": c_tok, "latency_s": round(time.time() - t_call, 2)})
        return text

    findings, summary, warnings = [], "", []
    report_status, finish_reason = "none", None
    tool_calls = parse_errors = consecutive_errors = steps = 0
    reprompt = (
        "Your last reply was not a single valid JSON object. Reply with exactly one JSON object "
        'like {"tool": "list_files", "args": {}} and nothing else.'
    )

    def try_finish(action):
        nonlocal findings, summary, warnings
        findings, summary, warnings = validate_findings(action["args"])
        return True

    try:
        while steps < args.max_steps:
            if time.time() - t0 > args.max_seconds:
                finish_reason = "time_limit"
                break
            if sum(len(m["content"]) for m in messages) > args.max_context_chars:
                finish_reason = "context_limit"
                break
            steps += 1
            reply = strip_think(call_model())
            messages.append({"role": "assistant", "content": reply or "(empty reply)"})
            action, extra = parse_action(reply)
            if action is None:
                parse_errors += 1
                consecutive_errors += 1
                print(f"  step {steps}: unparseable reply", file=sys.stderr)
                if consecutive_errors >= 3:
                    finish_reason = "parse_errors"
                    break
                messages.append({"role": "user", "content": reprompt})
                log({"type": "user", "content": reprompt})
                continue
            consecutive_errors = 0
            tool = action["tool"]
            print(f"  step {steps}/{args.max_steps}: {tool} {json.dumps(action['args'])[:90]}")
            if tool == "finish":
                try:
                    try_finish(action)
                    report_status, finish_reason = "submitted", "finished"
                    break
                except ValueError as e:
                    result = f"ERROR: {e}"
            elif tool in tools_allowed:
                tool_calls += 1
                try:
                    result = ws.call(tool, action["args"])
                except ToolError as e:
                    result = f"ERROR: {e}"
            else:
                result = f"ERROR: unknown tool '{tool}'. Available: {', '.join(tools_allowed)}."
            note = "\n(Note: only the first JSON action in your reply was executed.)" if extra else ""
            user_msg = (
                f"TOOL RESULT ({tool}):\n{result}{note}\n\n"
                f"(Steps used: {steps}/{args.max_steps}. Reply with exactly one JSON action.)"
            )
            messages.append({"role": "user", "content": user_msg})
            log({"type": "tool_result", "tool": tool, "content": result})

        if finish_reason is None:  # step budget used up without a report: ask once for a final answer
            finish_reason = "step_limit"
            force = ("Step limit reached. Reply now with the finish action and your best findings "
                     '(use "findings": [] if you found nothing exploitable).')
            messages.append({"role": "user", "content": force})
            log({"type": "user", "content": force})
            reply = strip_think(call_model())
            action, _ = parse_action(reply)
            if action and action["tool"] == "finish":
                try:
                    try_finish(action)
                    report_status = "forced"
                except ValueError:
                    pass
    except KeyboardInterrupt:
        finish_reason = "interrupted"
        print("\ninterrupted; saving partial run", file=sys.stderr)
    except LLMError as e:
        finish_reason = "llm_error"
        log({"type": "error", "content": str(e)})
        print(f"  LLM error: {e}", file=sys.stderr)
    finally:
        transcript.close()
        shutil.rmtree(tmp_root, ignore_errors=True)

    wall = round(time.time() - t0, 1)
    # findings.json is deliberately free of task/variant info so grading can be blinded.
    (run_dir / "findings.json").write_text(
        json.dumps({"run_id": run_id, "report_status": report_status, "summary": summary,
                    "findings": findings, "schema_warnings": warnings}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    params = {
        "temperature": args.temperature, "max_steps": args.max_steps, "max_seconds": args.max_seconds,
        "max_output_tokens": args.max_output_tokens, "max_tool_chars": args.max_tool_chars,
        "max_context_chars": args.max_context_chars, "min_interval": args.min_interval,
        "prompt_sha256": prompt_hash, "scaffold_version": SCAFFOLD_VERSION, "git_commit": git_commit(),
    }
    append_mapping(out_dir, {
        "run_id": run_id, "started_utc": started.isoformat(timespec="seconds"),
        "task": str(args.task), "variant": args.variant, "model": client.model,
        "base_url_host": urlparse(client.url).netloc, "steps": steps, "tool_calls": tool_calls,
        "parse_errors": parse_errors, "tokens_in": stats["tokens_in"], "tokens_out": stats["tokens_out"],
        "usage_estimated_calls": stats["estimated_calls"], "wall_seconds": wall,
        "finish_reason": finish_reason, "report_status": report_status,
        "findings_count": len(findings), "params": json.dumps(params),
    })
    print(f"run {run_id}: {report_status}, {len(findings)} finding(s), {steps} steps, "
          f"{stats['tokens_in']} in / {stats['tokens_out']} out tokens, {wall}s -> {run_dir / 'findings.json'}")
    return run_id


def build_parser():
    p = argparse.ArgumentParser(description="evmbench-pilot scaffold v0 (read-only audit agent)")
    p.add_argument("--task", required=True, help="version folder, e.g. tasks/toy-vault/vuln")
    p.add_argument("--variant", default="v0", help=f"one of: {', '.join(VARIANT_TOOLS)}")
    p.add_argument("--out", default="runs", help="output folder (default: runs/)")
    p.add_argument("--repeats", type=int, default=1, help="run this many times in a row")
    p.add_argument("--max-steps", type=int, default=25)
    p.add_argument("--max-seconds", type=int, default=900)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--max-output-tokens", type=int, default=4096)
    p.add_argument("--max-tool-chars", type=int, default=12_000)
    p.add_argument("--max-context-chars", type=int, default=400_000,
                   help="abort a run if the conversation exceeds this many characters (protects quotas)")
    p.add_argument("--min-interval", type=float, default=None,
                   help="minimum seconds between API calls (free tiers); default: $LLM_MIN_INTERVAL or 0")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--retries", type=int, default=6)
    return p


def main(argv=None) -> int:
    load_dotenv(find_dotenv(usecwd=True))
    try:  # keep Windows consoles from crashing on unusual characters
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    if args.variant not in VARIANT_TOOLS:
        sys.exit(f"error: variant '{args.variant}' is not implemented yet. Available: {', '.join(VARIANT_TOOLS)}")
    prompt_file = PROMPT_DIR / f"{args.variant}.md"
    if not prompt_file.is_file():
        sys.exit(f"error: prompt file missing: {prompt_file}")

    base_url, model, key = (os.getenv(k) for k in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"))
    if not (base_url and model and key):
        sys.exit(
            "error: set LLM_BASE_URL, LLM_MODEL and LLM_API_KEY (copy .env.example to .env).\n"
            "Base URL examples: Gemini https://generativelanguage.googleapis.com/v1beta/openai/ | "
            "OpenRouter https://openrouter.ai/api/v1 | Groq https://api.groq.com/openai/v1 | "
            "DeepSeek https://api.deepseek.com | local mock http://127.0.0.1:8000/v1"
        )
    if args.min_interval is None:
        args.min_interval = float(os.getenv("LLM_MIN_INTERVAL", "0") or 0)

    task = Path(args.task)
    check_task_dir(task)
    args.task = task

    raw_prompt = prompt_file.read_text(encoding="utf-8")
    system_prompt = raw_prompt.replace("{MAX_STEPS}", str(args.max_steps))
    prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()[:12]

    client = LLMClient(base_url, model, key, temperature=args.temperature,
                       max_output_tokens=args.max_output_tokens, timeout=args.timeout,
                       min_interval=args.min_interval, max_retries=args.retries)
    for i in range(args.repeats):
        if args.repeats > 1:
            print(f"--- repeat {i + 1}/{args.repeats} ---")
        run_once(args, client, system_prompt, prompt_hash, VARIANT_TOOLS[args.variant])
    print("Grade runs/<id>/findings.json first; open runs/_mapping.csv only after grading.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
