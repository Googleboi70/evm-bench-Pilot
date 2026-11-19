"""Read-only workspace tools for scaffold v0.

Every path the agent supplies is resolved against the workspace root and rejected if
it escapes it. Nothing in this module executes code or writes files.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

# Directories hidden from list_files / grep unless include_deps=true.
SKIP_DIRS = {".git", "node_modules", "out", "cache", "broadcast", "lib", "__pycache__"}
TEXT_EXTS = {
    ".sol", ".vy", ".md", ".toml", ".json", ".txt", ".yml", ".yaml",
    ".rs", ".js", ".ts", ".py", ".sh", ".cfg", ".ini",
}
MAX_FILE_BYTES = 1_000_000


class ToolError(Exception):
    """Bad tool call. The message is shown to the model so it can correct itself."""


def clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... truncated {len(text) - limit} characters ...]"


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _as_int(value, name: str, default=None):
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolError(f"{name} must be an integer")


class Workspace:
    def __init__(self, root, max_chars=12_000, max_read_lines=400, max_list=300, max_grep=80):
        self.root = Path(root).resolve()
        self.max_chars = max_chars
        self.max_read_lines = max_read_lines
        self.max_list = max_list
        self.max_grep = max_grep

    # ------------------------------------------------------------------ helpers
    def _resolve(self, rel) -> Path:
        if rel is None:
            rel = "."
        if not isinstance(rel, str):
            raise ToolError("path must be a string")
        rel = rel.strip() or "."
        if rel.startswith(("/", "\\", "~")) or re.match(r"^[A-Za-z]:", rel):
            raise ToolError("absolute paths are not allowed; use a path relative to the workspace root")
        full = (self.root / rel).resolve()
        if full != self.root and self.root not in full.parents:
            raise ToolError("path is outside the workspace")
        return full

    def _rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def _iter_files(self, base: Path, include_deps: bool):
        if base.is_file():
            yield base
            return
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d != ".git" and (include_deps or d not in SKIP_DIRS)
            )
            for name in sorted(filenames):
                yield Path(dirpath) / name

    @staticmethod
    def _describe(f: Path) -> str:
        try:
            size = f.stat().st_size
        except OSError:
            return "unreadable"
        if f.suffix.lower() in TEXT_EXTS and size <= MAX_FILE_BYTES:
            try:
                with f.open("rb") as fh:
                    n = sum(1 for _ in fh)
                return f"{n} lines"
            except OSError:
                return "unreadable"
        return f"{size} bytes"

    # ------------------------------------------------------------------- tools
    def list_files(self, path=".", max_depth=4, include_deps=False) -> str:
        base = self._resolve(path)
        if not base.exists():
            raise ToolError(f"path not found: {path}")
        depth = max(1, _as_int(max_depth, "max_depth", 4))
        include_deps = _as_bool(include_deps)
        entries, total = [], 0
        for f in self._iter_files(base, include_deps):
            if base.is_dir() and len(f.relative_to(base).parts) > depth:
                continue
            total += 1
            if len(entries) < self.max_list:
                entries.append(f"{self._rel(f)}  ({self._describe(f)})")
        head = (
            f"Files under '{self._rel(base)}' "
            "(dependency/build dirs such as lib/, out/, cache/ are hidden unless include_deps=true):" 
        )
        if not entries:
            return head + "\n(no files found)"
        out = head + "\n" + "\n".join(entries)
        if total > len(entries):
            out += f"\n[... {total - len(entries)} more files not shown; narrow the path]"
        return out

    def read_file(self, path, start_line=1, end_line=None) -> str:
        f = self._resolve(path)
        if not f.exists():
            raise ToolError(f"file not found: {path}")
        if f.is_dir():
            raise ToolError(f"{path} is a directory; use list_files")
        if f.stat().st_size > MAX_FILE_BYTES * 3:
            raise ToolError("file is too large to read")
        raw = f.read_bytes()
        if b"\x00" in raw[:4096]:
            raise ToolError("binary file; cannot display")
        lines = raw.decode("utf-8", errors="replace").splitlines()
        total = len(lines)
        start = max(1, _as_int(start_line, "start_line", 1))
        end = _as_int(end_line, "end_line", None)
        if end is None or end > total:
            end = total
        if total == 0:
            return f"File: {self._rel(f)} (empty)"
        if start > total:
            return f"File: {self._rel(f)} has only {total} lines; start_line={start} is past the end."
        if end < start:
            raise ToolError("end_line must be >= start_line")
        note = ""
        if end - start + 1 > self.max_read_lines:
            end = start + self.max_read_lines - 1
            note = f"\n[output capped at {self.max_read_lines} lines; call again with start_line={end + 1}]"
        body = "\n".join(f"{i:>5} | {lines[i - 1]}" for i in range(start, end + 1))
        return f"File: {self._rel(f)} (lines {start}-{end} of {total})\n{body}{note}"

    def grep(self, pattern, path=".", ignore_case=False, include_deps=False) -> str:
        if not isinstance(pattern, str) or not pattern:
            raise ToolError("pattern must be a non-empty string")
        try:
            rx = re.compile(pattern, re.IGNORECASE if _as_bool(ignore_case) else 0)
        except re.error as e:
            raise ToolError(f"invalid regex: {e}")
        base = self._resolve(path)
        if not base.exists():
            raise ToolError(f"path not found: {path}")
        include_deps = _as_bool(include_deps)
        matches, truncated = [], False
        for f in self._iter_files(base, include_deps):
            if f.suffix.lower() not in TEXT_EXTS:
                continue
            try:
                if f.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = self._rel(f)
            for n, line in enumerate(text.splitlines(), 1):
                if rx.search(line[:2000]):
                    if len(matches) >= self.max_grep:
                        truncated = True
                        break
                    matches.append(f"{rel}:{n}: {line.strip()[:200]}")
            if truncated:
                break
        if not matches:
            return f"No matches for /{pattern}/ under '{self._rel(base)}'."
        out = f"{len(matches)} match(es) for /{pattern}/:\n" + "\n".join(matches)
        if truncated:
            out += f"\n[stopped after {self.max_grep} matches; narrow the pattern or path]"
        return out

    # --------------------------------------------------------------- dispatcher
    def call(self, name: str, args) -> str:
        if not isinstance(args, dict):
            raise ToolError("args must be a JSON object")
        fn = {"list_files": self.list_files, "read_file": self.read_file, "grep": self.grep}.get(name)
        if fn is None:
            raise ToolError(f"unknown tool: {name}")
        try:
            return clip(fn(**args), self.max_chars)
        except TypeError as e:
            raise ToolError(f"bad arguments for {name}: {e}")
