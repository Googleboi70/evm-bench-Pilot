"""Unit tests for scaffold/tools.py and the action parser. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scaffold"))

from tools import ToolError, Workspace  # noqa: E402
from agent import parse_action, validate_findings  # noqa: E402


def make_ws(tmp):
    root = Path(tmp) / "ws"
    (root / "src").mkdir(parents=True)
    (root / "lib" / "dep").mkdir(parents=True)
    (root / "src" / "A.sol").write_text("contract A {\n  function f() external {}\n}\n")
    (root / "lib" / "dep" / "D.sol").write_text("contract D {}\n")
    (Path(tmp) / "secret.txt").write_text("top secret")
    return Workspace(root, max_chars=500, max_read_lines=2)


class ToolsTest(unittest.TestCase):
    def test_list_hides_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            out = ws.list_files(".")
            self.assertIn("src/A.sol", out)
            self.assertNotIn("lib/dep/D.sol", out)
            self.assertIn("lib/dep/D.sol", ws.list_files(".", include_deps=True))

    def test_rejects_escape_and_absolute_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            for bad in ["../secret.txt", "src/../../secret.txt", "/etc/passwd", "C:\\Windows", "~/x"]:
                with self.assertRaises(ToolError, msg=bad):
                    ws.read_file(bad)

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            os.symlink(Path(tmp) / "secret.txt", ws.root / "src" / "link.txt")
            with self.assertRaises(ToolError):
                ws.read_file("src/link.txt")

    def test_read_ranges_and_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            out = ws.read_file("src/A.sol")  # 3 lines, cap is 2
            self.assertIn("capped at 2 lines", out)
            self.assertIn("start_line=3", out)
            self.assertIn("    2 |   function f()", ws.read_file("src/A.sol", 2, 2))
            self.assertIn("past the end", ws.read_file("src/A.sol", 99))

    def test_grep(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            self.assertIn("src/A.sol:2:", ws.grep("function"))
            self.assertIn("No matches", ws.grep("nothing_here"))
            self.assertNotIn("D.sol", ws.grep("contract"))
            with self.assertRaises(ToolError):
                ws.grep("(unclosed")

    def test_dispatcher_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            with self.assertRaises(ToolError):
                ws.call("rm_rf", {})
            with self.assertRaises(ToolError):
                ws.call("read_file", {"nonsense": 1})
            with self.assertRaises(ToolError):
                ws.call("read_file", "not-a-dict")

    def test_output_clipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = make_ws(tmp)
            (ws.root / "src" / "big.sol").write_text("x" * 5000 + "\n")
            self.assertIn("truncated", ws.call("read_file", {"path": "src/big.sol"}))


class RetryDelayTest(unittest.TestCase):
    class R:
        def __init__(self, headers=None, text=""):
            self.headers, self.text = headers or {}, text

    def test_header_body_and_backoff(self):
        from agent import LLMClient
        self.assertEqual(LLMClient._retry_delay(self.R({"Retry-After": "7"}), 0), 7.0)
        self.assertEqual(LLMClient._retry_delay(self.R(text='{"retryDelay": "30s"}'), 0), 31.0)
        self.assertEqual(LLMClient._retry_delay(self.R(), 2), 20.0)


class ParserTest(unittest.TestCase):
    def test_plain_and_fenced_json(self):
        a, extra = parse_action('{"tool": "list_files", "args": {"path": "."}}')
        self.assertEqual(a, {"tool": "list_files", "args": {"path": "."}})
        self.assertFalse(extra)
        a, _ = parse_action('Sure:\n```json\n{"tool": "grep", "args": {"pattern": "call"}}\n```')
        self.assertEqual(a["tool"], "grep")

    def test_think_blocks_and_multiple_actions(self):
        a, extra = parse_action(
            '<think>{"tool": "finish"}</think>{"tool": "read_file", "args": {"path": "a"}} '
            '{"tool": "list_files", "args": {}}'
        )
        self.assertEqual(a["tool"], "read_file")
        self.assertTrue(extra)

    def test_lenient_forms(self):
        a, _ = parse_action('{"tool": "read_file", "path": "src/A.sol"}')
        self.assertEqual(a["args"], {"path": "src/A.sol"})
        a, _ = parse_action('{"summary": "done", "findings": []}')
        self.assertEqual(a["tool"], "finish")

    def test_garbage(self):
        self.assertEqual(parse_action("no json here"), (None, False))
        self.assertEqual(parse_action('{"unclosed": '), (None, False))

    def test_validate_findings(self):
        f, s, w = validate_findings({"summary": "x", "findings": [{"title": "t"}]})
        self.assertEqual(len(f), 1)
        self.assertTrue(w)
        with self.assertRaises(ValueError):
            validate_findings({"findings": "none"})
        with self.assertRaises(ValueError):
            validate_findings({"findings": ["oops"]})


if __name__ == "__main__":
    unittest.main()
