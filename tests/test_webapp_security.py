"""
Security tests for the web interface.

Several of these replay attacks that previously succeeded against this
codebase. `test_arbitrary_file_read_is_rejected` in particular reproduces a
confirmed exploit: a POST naming any readable path had its contents returned in
the response, and with an API key configured that content was forwarded to a
third-party provider. These tests exist so those paths stay closed.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from webapp.app import create_app
from webapp.scan_service import OUTPUT_ROOT_ENV, _resolve_output_dir, output_root
from webapp.security import (
    CSRF_FORM_FIELD,
    csrf_token_is_valid,
    get_csrf_token,
    is_loopback_host,
    resolve_within,
    select_allowed_file,
)


class TestPathConfinement(unittest.TestCase):
    """resolve_within must not be escapable by traversal, absolute paths, or symlinks."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        (self.base / "inside.txt").write_text("ok", encoding="utf-8")
        (self.base / "sub").mkdir()
        (self.base / "sub" / "deep.txt").write_text("ok", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_relative_path_inside_base_is_allowed(self) -> None:
        self.assertIsNotNone(resolve_within(self.base, "inside.txt"))
        self.assertIsNotNone(resolve_within(self.base, "sub/deep.txt"))

    def test_base_itself_is_allowed(self) -> None:
        self.assertIsNotNone(resolve_within(self.base, str(self.base)))

    def test_parent_traversal_is_rejected(self) -> None:
        for attempt in ("..", "../", "../../etc/passwd", "sub/../../outside.txt"):
            with self.subTest(attempt=attempt):
                self.assertIsNone(resolve_within(self.base, attempt))

    def test_absolute_path_outside_base_is_rejected(self) -> None:
        outside = self.base.parent / "definitely_outside_riskripple.txt"
        self.assertIsNone(resolve_within(self.base, str(outside)))

    def test_empty_and_none_are_rejected(self) -> None:
        self.assertIsNone(resolve_within(self.base, ""))
        self.assertIsNone(resolve_within(self.base, "   "))
        self.assertIsNone(resolve_within(self.base, None))

    def test_sibling_directory_with_shared_prefix_is_rejected(self) -> None:
        """A path like /tmp/base_evil must not pass a check against /tmp/base."""
        sibling = self.base.parent / (self.base.name + "_evil")
        self.assertIsNone(resolve_within(self.base, str(sibling)))


class TestAllowedFileSelection(unittest.TestCase):
    """The backend must honour the file list the interface offered."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.offered = self.base / "offered.py"
        self.offered.write_text("x = 1\n", encoding="utf-8")
        self.not_offered = self.base / "secret.py"
        self.not_offered.write_text("y = 2\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_offered_file_is_accepted(self) -> None:
        self.assertEqual(self.offered, select_allowed_file(str(self.offered), [self.offered]))

    def test_file_not_in_list_is_rejected(self) -> None:
        self.assertIsNone(select_allowed_file(str(self.not_offered), [self.offered]))

    def test_empty_selection_is_rejected(self) -> None:
        self.assertIsNone(select_allowed_file("", [self.offered]))

    def test_equivalent_spelling_of_offered_path_is_accepted(self) -> None:
        awkward = str(self.base / "sub" / ".." / "offered.py")
        self.assertEqual(self.offered, select_allowed_file(awkward, [self.offered]))


class TestCsrfTokens(unittest.TestCase):
    def test_token_is_stable_within_a_session(self) -> None:
        session: dict = {}
        self.assertEqual(get_csrf_token(session), get_csrf_token(session))

    def test_token_differs_between_sessions(self) -> None:
        self.assertNotEqual(get_csrf_token({}), get_csrf_token({}))

    def test_validation_rejects_wrong_and_missing_tokens(self) -> None:
        session: dict = {}
        token = get_csrf_token(session)
        self.assertTrue(csrf_token_is_valid(session, token))
        self.assertFalse(csrf_token_is_valid(session, "wrong"))
        self.assertFalse(csrf_token_is_valid(session, ""))
        self.assertFalse(csrf_token_is_valid(session, None))
        self.assertFalse(csrf_token_is_valid({}, token))


class TestLoopbackDetection(unittest.TestCase):
    def test_loopback_hosts(self) -> None:
        for host in ("127.0.0.1", "localhost", "::1", "127.0.0.5"):
            with self.subTest(host=host):
                self.assertTrue(is_loopback_host(host))

    def test_exposed_hosts(self) -> None:
        for host in ("0.0.0.0", "192.168.1.10", "example.com", ""):
            with self.subTest(host=host):
                self.assertFalse(is_loopback_host(host))


class TestOutputDirectoryConfinement(unittest.TestCase):
    """Report writing must not be steerable outside the output root."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._previous = os.environ.get(OUTPUT_ROOT_ENV)
        os.environ[OUTPUT_ROOT_ENV] = self._tmp.name

    def tearDown(self) -> None:
        if self._previous is None:
            os.environ.pop(OUTPUT_ROOT_ENV, None)
        else:
            os.environ[OUTPUT_ROOT_ENV] = self._previous
        self._tmp.cleanup()

    def test_relative_output_dir_is_allowed(self) -> None:
        resolved = _resolve_output_dir("output")
        self.assertTrue(resolved.is_relative_to(output_root()))

    def test_absolute_path_outside_root_is_refused(self) -> None:
        outside = str(Path(self._tmp.name).resolve().parent / "riskripple_escape")
        with self.assertRaises(ValueError):
            _resolve_output_dir(outside)

    def test_traversal_is_refused(self) -> None:
        for attempt in ("../escape", "output/../../escape"):
            with self.subTest(attempt=attempt):
                with self.assertRaises(ValueError):
                    _resolve_output_dir(attempt)


class TestRequestLevelProtections(unittest.TestCase):
    """End-to-end checks through the Flask test client."""

    def setUp(self) -> None:
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _csrf_token(self) -> str:
        """Fetch a page and read the token the server issued to this client."""
        self.client.get("/scan")
        with self.client.session_transaction() as session:
            return get_csrf_token(session)

    def test_secret_key_is_not_a_shared_constant(self) -> None:
        self.assertNotEqual(self.app.secret_key, "dev-key")
        self.assertGreaterEqual(len(str(self.app.secret_key)), 32)

    def test_post_without_csrf_token_is_rejected(self) -> None:
        response = self.client.post("/ai-review", data={"action": "load_files", "target": "."})
        self.assertEqual(400, response.status_code)

    def test_post_with_wrong_csrf_token_is_rejected(self) -> None:
        response = self.client.post(
            "/ai-review",
            data={"action": "load_files", "target": ".", CSRF_FORM_FIELD: "forged"},
        )
        self.assertEqual(400, response.status_code)

    def test_post_with_valid_csrf_token_is_accepted(self) -> None:
        # Scan an isolated directory, never the shared system temp: on a CI
        # runner that holds unrelated and sometimes unreadable files.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "clean.py").write_text("value = 1\n", encoding="utf-8")
            token = self._csrf_token()
            response = self.client.post(
                "/tools/secrets",
                data={"target": tmp, CSRF_FORM_FIELD: token},
            )
        self.assertEqual(200, response.status_code)

    def test_get_requests_need_no_token(self) -> None:
        for route in ("/", "/scan", "/runs", "/rules", "/ai-review", "/tools/secrets", "/cli"):
            with self.subTest(route=route):
                self.assertEqual(200, self.client.get(route).status_code)

    def test_arbitrary_file_read_is_rejected(self) -> None:
        """
        Replays a previously confirmed exploit.

        Posting an arbitrary path as `selected_file` used to return that file's
        contents in the response, and forward them to the AI provider when a key
        was configured. The file must now be one the target actually enumerated.
        """
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / "confidential.txt"
            marker = "TOP_SECRET_MARKER_VALUE"
            secret.write_text(marker, encoding="utf-8")

            token = self._csrf_token()
            response = self.client.post(
                "/ai-review",
                data={
                    "action": "load_file",
                    "target": str(Path(__file__).resolve().parents[1]),
                    "selected_file": str(secret),
                    CSRF_FORM_FIELD: token,
                },
            )

            self.assertEqual(200, response.status_code)
            body = response.data.decode("utf-8", "ignore")
            self.assertNotIn(marker, body, "file contents outside the target were disclosed")

    def test_file_outside_target_is_rejected_even_when_readable(self) -> None:
        """A real, readable, source-like file still fails if the target did not offer it."""
        with tempfile.TemporaryDirectory() as outside:
            planted = Path(outside) / "elsewhere.py"
            planted.write_text("SECRET_CONSTANT = 'do-not-leak'\n", encoding="utf-8")

            token = self._csrf_token()
            response = self.client.post(
                "/ai-review",
                data={
                    "action": "load_file",
                    "target": str(Path(__file__).resolve().parents[1]),
                    "selected_file": str(planted),
                    CSRF_FORM_FIELD: token,
                },
            )
            self.assertNotIn("do-not-leak", response.data.decode("utf-8", "ignore"))


if __name__ == "__main__":
    unittest.main()
