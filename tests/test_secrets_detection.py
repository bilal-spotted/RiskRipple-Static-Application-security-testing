"""
Tests for shared credential detection.

The placeholder heuristics carry real risk in both directions: too aggressive
and a live credential is downgraded to LOW, too timid and every documentation
example is reported as critical. The tests below pin both edges, using values
assembled at runtime so this file contains no literal that matches a credential
pattern (which the project's own pre-commit hook would otherwise block).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.secrets_detection import (
    is_env_file,
    is_env_template,
    is_scannable_text_file,
    looks_like_placeholder,
    scan_file,
    scan_text,
)


def _aws() -> str:
    return "AKIA" + "3ZK7QW9XMPLR2VDN"


def _openai() -> str:
    return "sk-" + "Rr4TmZ9qXw2LvB7nK3sD8fG1hJ6pY0cAeUt5ViQo"


def _github() -> str:
    return "ghp_" + "9Kq2mZx7RvB3nT8wYcF4jH6sL1pD0aQeUgIo"


class TestPlaceholderRecognition(unittest.TestCase):
    def test_documentation_examples_are_placeholders(self) -> None:
        known = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ",
            "your_api_key_here",
            "sk-CHANGEME000000000000000000000000000000",
            "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ]
        for value in known:
            with self.subTest(value=value):
                self.assertTrue(looks_like_placeholder(value))

    def test_realistic_keys_are_not_placeholders(self) -> None:
        """The critical direction: a real credential must never be downgraded."""
        for value in (_aws(), _openai(), _github()):
            with self.subTest(value=value[:12]):
                self.assertFalse(
                    looks_like_placeholder(value),
                    "a high-entropy credential was misread as a placeholder",
                )

    def test_empty_value_is_not_a_placeholder(self) -> None:
        self.assertFalse(looks_like_placeholder(""))


class TestScanText(unittest.TestCase):
    def test_detects_each_supported_provider(self) -> None:
        content = f"a={_aws()}\nb={_openai()}\nc={_github()}\n"
        names = {m.name for m in scan_text(content)}
        self.assertIn("AWS access key", names)
        self.assertIn("OpenAI API key", names)
        self.assertIn("GitHub token", names)

    def test_clean_text_yields_nothing(self) -> None:
        self.assertEqual([], scan_text("total = 1 + 2\nname = 'hello world'\n"))

    def test_one_match_per_signature(self) -> None:
        """Twenty copies of a key are one problem, not twenty findings."""
        content = "\n".join(f"key{i} = '{_aws()}'" for i in range(20))
        self.assertEqual(1, len([m for m in scan_text(content) if m.name == "AWS access key"]))

    def test_real_key_beside_a_placeholder_is_reported_as_real(self) -> None:
        content = f"example = 'AKIAIOSFODNN7EXAMPLE'\nlive = '{_aws()}'\n"
        matches = [m for m in scan_text(content) if m.name == "AWS access key"]
        self.assertEqual(1, len(matches))
        self.assertFalse(
            matches[0].is_placeholder,
            "a real key sharing a file with an example must not be downgraded",
        )

    def test_placeholder_alone_is_flagged_as_placeholder(self) -> None:
        matches = scan_text("example = 'AKIAIOSFODNN7EXAMPLE'\n")
        self.assertEqual(1, len(matches))
        self.assertTrue(matches[0].is_placeholder)

    def test_private_key_block_detected(self) -> None:
        header = "-----BEGIN RSA " + "PRIVATE KEY-----"
        footer = "-----END RSA " + "PRIVATE KEY-----"
        content = f"{header}\nMIIEow==\n{footer}\n"
        self.assertIn("Private key material", {m.name for m in scan_text(content)})


class TestEnvFileClassification(unittest.TestCase):
    def test_env_variants_are_secret_files(self) -> None:
        for name in (".env", ".env.local", ".env.production", ".env.secret"):
            with self.subTest(name=name):
                self.assertTrue(is_env_file(name))
                self.assertFalse(is_env_template(name))

    def test_templates_are_not_secret_files(self) -> None:
        """The single most visible false positive in an earlier self-scan."""
        for name in (".env.example", ".env.sample", ".env.template", ".env.dist"):
            with self.subTest(name=name):
                self.assertFalse(is_env_file(name))
                self.assertTrue(is_env_template(name))

    def test_unrelated_names_are_neither(self) -> None:
        for name in ("environment.py", "settings.json", "readme.md"):
            with self.subTest(name=name):
                self.assertFalse(is_env_file(name))
                self.assertFalse(is_env_template(name))


class TestScannableFiles(unittest.TestCase):
    def test_text_types_are_scannable(self) -> None:
        for name in ("a.py", "b.json", "c.yaml", "d.md", ".env", "e.toml"):
            with self.subTest(name=name):
                self.assertTrue(is_scannable_text_file(name))

    def test_binary_types_are_skipped(self) -> None:
        for name in ("a.png", "b.pyc", "c.zip", "d.exe"):
            with self.subTest(name=name):
                self.assertFalse(is_scannable_text_file(name))


class TestScanFile(unittest.TestCase):
    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual([], scan_file(Path("does_not_exist_xyz.txt")))

    def test_oversized_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.txt"
            big.write_text("x" * 2000 + _aws(), encoding="utf-8")
            self.assertEqual([], scan_file(big, max_bytes=1000))


if __name__ == "__main__":
    unittest.main()
