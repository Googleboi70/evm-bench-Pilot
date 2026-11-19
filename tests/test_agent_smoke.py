"""End-to-end tests: the agent loop against the offline mock server (no API, no cost).

Run: python -m unittest discover -s tests
"""
import csv
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scaffold"))
sys.path.insert(0, str(ROOT / "scripts"))

import agent  # noqa: E402
from mock_llm_server import make_server  # noqa: E402

TOY = ROOT / "tasks" / "toy-vault" / "vuln"


class SmokeTest(unittest.TestCase):
    def run_agent(self, mode="normal", findings="one", extra=None):
        server = make_server(0, mode, findings)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        out = tempfile.mkdtemp()
        env = {"LLM_BASE_URL": f"http://127.0.0.1:{port}/v1", "LLM_MODEL": "mock", "LLM_API_KEY": "dummy"}
        argv = ["--task", str(TOY), "--out", out, "--retries", "0"] + (extra or [])
        try:
            with mock.patch.dict(os.environ, env):
                agent.main(argv)
        finally:
            server.shutdown()
            server.server_close()
        out = Path(out)
        with (out / "_mapping.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        run_dir = out / rows[-1]["run_id"]
        return rows[-1], run_dir

    def test_normal_run_and_blinding(self):
        row, run_dir = self.run_agent()
        findings = json.loads((run_dir / "findings.json").read_text())
        self.assertEqual(findings["report_status"], "submitted")
        self.assertEqual(len(findings["findings"]), 1)
        self.assertEqual(row["finish_reason"], "finished")
        self.assertGreater(int(row["tokens_in"]), 0)
        self.assertEqual(row["usage_estimated_calls"], "0")
        # blinding: nothing the agent sees or the grader opens names the version or temp folder
        text = (run_dir / "transcript.jsonl").read_text() + (run_dir / "findings.json").read_text()
        self.assertNotIn("tasks/toy-vault", text)
        self.assertNotIn("audit_", text)
        self.assertIsNone(re.search(r"\bvuln\b|\bfixed\b|\bgrader\b", text))
        self.assertNotIn("task", json.dumps(findings).lower().replace("tasks", ""))
        # the script's own files are laid out as the README says
        self.assertTrue((run_dir / "transcript.jsonl").exists())

    def test_clean_empty_report_is_distinct_from_no_report(self):
        row, run_dir = self.run_agent(findings="none")
        f = json.loads((run_dir / "findings.json").read_text())
        self.assertEqual((f["report_status"], f["findings"]), ("submitted", []))

    def test_recovers_from_one_bad_reply(self):
        row, run_dir = self.run_agent(mode="garble_first")
        self.assertEqual(row["parse_errors"], "1")
        self.assertEqual(row["finish_reason"], "finished")

    def test_gives_up_after_three_bad_replies(self):
        row, run_dir = self.run_agent(mode="garble_always")
        self.assertEqual(row["finish_reason"], "parse_errors")
        self.assertEqual(json.loads((run_dir / "findings.json").read_text())["report_status"], "none")

    def test_step_limit_forces_a_report(self):
        row, run_dir = self.run_agent(mode="never_finish", extra=["--max-steps", "3"])
        self.assertEqual(row["finish_reason"], "step_limit")
        self.assertEqual(json.loads((run_dir / "findings.json").read_text())["report_status"], "forced")

    def test_retries_after_rate_limit(self):
        row, run_dir = self.run_agent(mode="rate_limit_once", extra=["--retries", "2"])
        self.assertEqual(row["finish_reason"], "finished")
        self.assertEqual(row["steps"], "4")

    def test_estimates_tokens_when_provider_sends_no_usage(self):
        row, run_dir = self.run_agent(mode="no_usage")
        self.assertEqual(row["usage_estimated_calls"], row["steps"])
        self.assertGreater(int(row["tokens_in"]), 0)

    def test_repeats_make_distinct_run_ids(self):
        server = make_server(0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        out = tempfile.mkdtemp()
        env = {"LLM_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}/v1",
               "LLM_MODEL": "mock", "LLM_API_KEY": "dummy"}
        with mock.patch.dict(os.environ, env):
            agent.main(["--task", str(TOY), "--out", out, "--repeats", "2"])
        server.shutdown()
        server.server_close()
        with (Path(out) / "_mapping.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["run_id"], rows[1]["run_id"])

    def test_refuses_task_parent_folder_and_grader_files(self):
        env = {"LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m", "LLM_API_KEY": "k"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env):
            parent = Path(tmp) / "task"
            (parent / "vuln" / "src").mkdir(parents=True)
            with self.assertRaises(SystemExit) as cm:
                agent.main(["--task", str(parent), "--out", tmp])
            self.assertIn("version folder", str(cm.exception))
            leaky = Path(tmp) / "leaky"
            (leaky / "test").mkdir(parents=True)
            (leaky / "test" / "Exploit.t.sol").write_text("// grader")
            with self.assertRaises(SystemExit) as cm:
                agent.main(["--task", str(leaky), "--out", tmp])
            self.assertIn("leak", str(cm.exception))

    def test_unimplemented_variant_and_missing_env(self):
        with self.assertRaises(SystemExit):
            agent.main(["--task", str(TOY), "--variant", "v1"])
        with mock.patch.dict(os.environ, {"LLM_BASE_URL": "", "LLM_MODEL": "", "LLM_API_KEY": ""}):
            with self.assertRaises(SystemExit) as cm:
                agent.main(["--task", str(TOY)])
            self.assertIn("LLM_BASE_URL", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
