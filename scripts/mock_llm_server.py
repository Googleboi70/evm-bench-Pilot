#!/usr/bin/env python3
"""A tiny fake OpenAI-compatible server for testing the scaffold offline, at zero cost.

It does not audit anything. It just plays a fixed script (list_files -> read_file -> grep
-> finish) so you can check that the agent loop, logging and output files all work.

    python scripts/mock_llm_server.py --port 8000 [--mode normal|garble_first|garble_always|never_finish|rate_limit_once|no_usage]
                                                  [--findings one|none]
Then run the agent with LLM_BASE_URL=http://127.0.0.1:8000/v1 LLM_MODEL=mock LLM_API_KEY=dummy.
"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FINDING = {
    "title": "Reentrancy in withdraw",
    "vulnerability_type": "reentrancy",
    "severity": "high",
    "location": "src/Vault.sol:withdraw",
    "description": "The balance is decreased only after the external call.",
    "attack_scenario": "An attacker contract re-enters withdraw() from its receive() function.",
    "confidence": "medium",
}


def action(tool, **args):
    return json.dumps({"tool": tool, "args": args})


def decide(messages, mode, findings):
    last = messages[-1]["content"]
    n_actions = sum(
        1 for m in messages if m["role"] == "assistant" and m["content"].lstrip().startswith("{")
    )
    if mode == "garble_always":
        return "I think the code looks interesting, let me think about it."
    if mode == "garble_first" and n_actions == 0 and "not a single valid JSON" not in last:
        return "Sure! I will start by looking around the project."
    if "Step limit reached" in last:
        return action("finish", summary="mock: forced finish", findings=[])
    if mode == "never_finish":
        return action("list_files", path=".")
    if n_actions == 0:
        return action("list_files", path=".")
    if n_actions == 1:
        m = re.search(r"([\w./-]*src/[\w./-]+\.sol)", last)
        return action("read_file", path=m.group(1) if m else "src/Vault.sol")
    if n_actions == 2:
        return action("grep", pattern=r"\.call\{", path="src")
    return action(
        "finish",
        summary="mock audit finished",
        findings=[FINDING] if findings == "one" else [],
    )


def make_server(port=0, mode="normal", findings="one"):
    state = {"limited": False}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if mode == "rate_limit_once" and not state["limited"]:
                state["limited"] = True
                data = json.dumps({"error": {"message": "rate limited (mock)"}}).encode()
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            messages = body.get("messages", [])
            content = decide(messages, mode, findings)
            payload = {
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                             "finish_reason": "stop"}],
            }
            if mode != "no_usage":
                payload["usage"] = {
                    "prompt_tokens": max(1, len(json.dumps(messages)) // 4),
                    "completion_tokens": max(1, len(content) // 4),
                }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--mode", default="normal",
                    choices=["normal", "garble_first", "garble_always", "never_finish",
                             "rate_limit_once", "no_usage"])
    ap.add_argument("--findings", default="one", choices=["one", "none"])
    a = ap.parse_args()
    server = make_server(a.port, a.mode, a.findings)
    print(f"mock LLM server on http://127.0.0.1:{a.port}/v1  (mode={a.mode}, findings={a.findings}); Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
