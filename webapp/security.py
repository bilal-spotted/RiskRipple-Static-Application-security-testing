"""
Security controls for the local web interface.

Risk Ripple's web GUI is a single-user tool bound to loopback by default, but
it accepts filesystem paths from form input and can forward file contents to a
third-party API. That combination deserves real controls rather than trust in
the browser, so the primitives live here: path confinement, CSRF tokens, and
host classification.

Keeping them in one module means they can be unit tested directly, instead of
only through request plumbing.
"""

from __future__ import annotations

import ipaddress
import secrets
from pathlib import Path
from typing import Any, Iterable, Optional, Union

# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

# Methods that must not change state, and so need no CSRF token.
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def get_csrf_token(session: Any) -> str:
    """
    Return this session's CSRF token, creating one on first use.

    The token is stored in the signed session cookie, so a cross-origin page can
    trigger a request but cannot read the value needed to make it succeed.
    """
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return str(token)


def csrf_token_is_valid(session: Any, submitted: Optional[str]) -> bool:
    """Constant-time comparison of a submitted CSRF token against the session's."""
    expected = session.get(CSRF_SESSION_KEY)
    if not expected or not submitted:
        return False
    return secrets.compare_digest(str(expected), str(submitted))


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


def resolve_within(base: Union[str, Path], candidate: Union[str, Path]) -> Optional[Path]:
    """
    Resolve ``candidate`` and return it only if it lands inside ``base``.

    Relative candidates are joined onto ``base``; absolute ones are taken as
    given and then checked. Both sides are fully resolved first, so ``..``
    segments and symlinks cannot be used to escape: a symlink pointing outside
    the base resolves to its real location and fails the containment check.

    Returns None when the path escapes, is malformed, or cannot be resolved.
    Callers must treat None as a refusal, never as "use the raw value".
    """
    if candidate is None or str(candidate).strip() == "":
        return None
    try:
        base_resolved = Path(base).expanduser().resolve()
        target = Path(candidate).expanduser()
        if not target.is_absolute():
            target = base_resolved / target
        target_resolved = target.resolve()
    except (OSError, ValueError, RuntimeError):
        # Malformed paths, invalid characters, or symlink loops.
        return None

    if target_resolved == base_resolved or target_resolved.is_relative_to(base_resolved):
        return target_resolved
    return None


def is_within(base: Union[str, Path], candidate: Union[str, Path]) -> bool:
    """True if ``candidate`` resolves to a location inside ``base``."""
    return resolve_within(base, candidate) is not None


def select_allowed_file(candidate: str, allowed: Iterable[Union[str, Path]]) -> Optional[Path]:
    """
    Return ``candidate`` only if it is one of the files actually offered.

    The AI review page builds its file list by scanning a target directory. This
    binds the submitted value to that enumeration, so the backend honours what
    the interface offered rather than accepting any path a request supplies.
    Membership is compared on resolved paths so equivalent spellings match.
    """
    if not candidate or not str(candidate).strip():
        return None
    try:
        resolved = Path(candidate).expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        return None

    for item in allowed:
        try:
            if Path(item).expanduser().resolve() == resolved:
                return resolved
        except (OSError, ValueError, RuntimeError):
            continue
    return None


# ---------------------------------------------------------------------------
# Host classification
# ---------------------------------------------------------------------------


def is_loopback_host(host: str) -> bool:
    """
    True if binding to ``host`` keeps the server reachable only from this machine.

    Used to warn when the interface is exposed beyond localhost, where its lack
    of authentication and its filesystem access become genuinely dangerous.
    """
    if not host:
        return False
    normalised = host.strip().strip("[]").lower()
    if normalised == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalised).is_loopback
    except ValueError:
        return False
