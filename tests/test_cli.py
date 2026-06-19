import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _run_scanner(args, cwd=None):
    repo_root = Path(__file__).resolve().parents[1]
    scanner = repo_root / "scanner.py"
    if cwd is None:
        cwd = repo_root
    cmd = [sys.executable, str(scanner)] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd))


class TestCLISmoke(unittest.TestCase):
    def test_cli_generates_all_reports(self):
        repo_root = Path(__file__).resolve().parents[1]
        samples = repo_root / "samples"

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)

            completed = _run_scanner(
                [
                    str(samples),
                    "--output-dir",
                    str(out_dir),
                    "--format",
                    "all",
                    "--workers",
                    "2",
                    "--top-files",
                    "5",
                ]
            )
            self.assertEqual(
                completed.returncode, 0, msg=completed.stdout + "\n" + completed.stderr
            )

            self.assertTrue((out_dir / "security_report.md").exists())
            self.assertTrue((out_dir / "security_report.html").exists())
            self.assertTrue((out_dir / "security_report.json").exists())
            self.assertTrue((out_dir / "security_report.sarif").exists())

    def test_help_exits_zero(self):
        completed = _run_scanner(["--help"])
        self.assertEqual(completed.returncode, 0)
        self.assertIn("target", completed.stdout)
        self.assertIn("--fail-on-severity", completed.stdout)
        self.assertIn("--fail-on-score", completed.stdout)

    def test_fail_on_severity_exits_one_when_high_found(self):
        repo_root = Path(__file__).resolve().parents[1]
        samples = repo_root / "samples"  # has HIGH findings
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            completed = _run_scanner(
                [
                    str(samples),
                    "--output-dir",
                    str(out_dir),
                    "--format",
                    "json",
                    "--fail-on-severity",
                    "HIGH",
                    "-q",
                ]
            )
            self.assertEqual(completed.returncode, 1)

    def test_fail_on_score_exits_one_when_above_threshold(self):
        repo_root = Path(__file__).resolve().parents[1]
        samples = repo_root / "samples"
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            completed = _run_scanner(
                [
                    str(samples),
                    "--output-dir",
                    str(out_dir),
                    "--format",
                    "json",
                    "--fail-on-score",
                    "0",
                    "-q",
                ]
            )
            self.assertEqual(completed.returncode, 1)

    def test_nonexistent_target_exits_one(self):
        completed = _run_scanner(["nonexistent_path_xyz_123", "--format", "json", "-q"])
        self.assertEqual(completed.returncode, 1)


if __name__ == "__main__":
    unittest.main()
