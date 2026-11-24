"""Unit test suite for ShadowAI-Scan Core (MIT)."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from shadowai_scan.__main__ import main as cli_main
from shadowai_scan.report_export import export_reports, render_markdown, render_terminal
from shadowai_scan.scanner import mask_secret, run_scan


class TestShadowAIScanCore(unittest.TestCase):
    def test_all_12_checks_and_masking(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            home = base / "home"
            bext = base / "bext"
            repo.mkdir()
            home.mkdir()
            bext.mkdir()

            (repo / ".env").write_text(
                "OPENAI_API_KEY=sk-proj-K9mPqR2vX8nL4wZ7cB3jF6hT5yD1aG0eS\n",
                encoding="utf-8",
            )
            (home / ".cursor").mkdir()
            (repo / "requirements.txt").write_text("openai==1.50.0\nlangchain==0.3.0\n", encoding="utf-8")
            (repo / "app.py").write_text('URL = "https://api.deepseek.com/v1/chat/completions"\n', encoding="utf-8")
            (repo / "chat_history.json").write_text('{"messages": []}', encoding="utf-8")
            (repo / "system_prompt.txt").write_text("db=postgresql://u:SecretPass99@10.1.2.3:5432/app\n", encoding="utf-8")
            (repo / "weights.pkl").write_bytes(b"pickle-bytes")
            ext_ver = bext / "ext001" / "1.0.0"
            ext_ver.mkdir(parents=True)
            (ext_ver / "manifest.json").write_text(
                json.dumps({"name": "Sider AI Sidebar", "host_permissions": ["<all_urls>"]}),
                encoding="utf-8",
            )
            wf = repo / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ai.yml").write_text(
                "name: AI\non: pull_request\njobs:\n  r:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: coderabbitai/coderabbit-action@main\n",
                encoding="utf-8",
            )

            report = run_scan(
                target_path=repo,
                repo_only=False,
                home_dir=home,
                env_override={},
                listeners_fn=lambda: [("0.0.0.0", 11434)],
                browser_ext_dirs=[bext],
            )
            self.assertEqual(len(report.checks), 12)
            by_id = {c.check_id: c for c in report.checks}
            for cid in ("SA-001", "SA-002", "SA-004", "SA-005", "SA-006", "SA-007", "SA-008", "SA-009", "SA-010", "SA-011"):
                self.assertEqual(by_id[cid].status, "FAIL", f"{cid} should FAIL")

            out = json.dumps(report.to_dict()) + render_markdown(report) + render_terminal(report, color=False)
            self.assertNotIn("K9mPqR2vX8nL4wZ7cB3jF6hT5yD1aG0eS", out)
            self.assertNotIn("SecretPass99", out)
            self.assertIn("sk-proj-****...****", out)

    def test_repo_only_and_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            allowlist = base / "approved-ai.json"
            allowlist.write_text(json.dumps({"approved_providers": ["anthropic"]}), encoding="utf-8")
            (repo / ".aiignore").write_text(".env\n*.key\n", encoding="utf-8")
            (repo / "requirements.txt").write_text("anthropic==0.45.0\n", encoding="utf-8")

            report = run_scan(target_path=repo, repo_only=True, allowlist_path=allowlist)
            by_id = {c.check_id: c for c in report.checks}
            self.assertEqual(by_id["SA-002"].status, "SKIP")
            self.assertEqual(by_id["SA-003"].status, "SKIP")
            self.assertEqual(by_id["SA-010"].status, "SKIP")
            self.assertEqual(by_id["SA-004"].status, "PASS")
            self.assertEqual(by_id["SA-012"].status, "PASS")
            self.assertEqual(report.score, 100)

    def test_md_json_export_and_cli_fail_under(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            out_dir = base / "out"
            repo.mkdir()
            (repo / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "scan",
                        "--path",
                        str(repo),
                        "--repo-only",
                        "--formats",
                        "terminal,md,json",
                        "--out-dir",
                        str(out_dir),
                        "--fail-under",
                        "90",
                        "--no-color",
                    ]
                )
            self.assertEqual(rc, 2)
            self.assertTrue((out_dir / "shadowai-report.md").is_file())
            self.assertTrue((out_dir / "shadowai-report.json").is_file())

    def test_mask_secret(self) -> None:
        self.assertEqual(mask_secret("sk-proj-1234567890abcdef"), "sk-proj-****...****")
        self.assertEqual(mask_secret("hf_abcdef1234567890"), "hf_****...****")


if __name__ == "__main__":
    unittest.main()
