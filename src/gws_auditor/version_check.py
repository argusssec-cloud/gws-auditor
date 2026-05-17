# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Version checking and self-update for GWS Security Auditor.

Queries PyPI at startup to determine whether a newer release is available
and optionally upgrades the package in-place.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

_PYPI_PACKAGE = "gws-security-auditor"
_PYPI_URL = f"https://pypi.org/pypi/{_PYPI_PACKAGE}/json"
_GITHUB_REPO = "argusssec-cloud/gws-auditor"
_GITHUB_LATEST_URL = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"
_GITHUB_RELEASES_PAGE = f"https://github.com/{_GITHUB_REPO}/releases"


# ------------------------------------------------------------------
# Version helpers
# ------------------------------------------------------------------

def get_installed_version() -> str:
    """Return the currently installed version string."""
    from . import __version__
    return __version__


def _fetch_pypi_latest(timeout: float) -> str | None:
    """Query PyPI for the latest release version. Returns ``None`` on failure."""
    try:
        req = urllib.request.Request(
            _PYPI_URL, headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except Exception:
        logger.debug("Failed to fetch latest version from PyPI", exc_info=True)
        return None


def _fetch_github_latest(timeout: float) -> str | None:
    """Query the GitHub Releases API for the latest tag. Strips a leading ``v``.

    Used as a fallback for frozen (PyInstaller) builds and any time the PyPI
    lookup fails — GitHub Releases is the canonical source of truth for the
    binary distribution.
    """
    try:
        req = urllib.request.Request(
            _GITHUB_LATEST_URL,
            headers={"Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            tag = data.get("tag_name", "")
            if tag.startswith("v"):
                tag = tag[1:]
            return tag or None
    except Exception:
        logger.debug("Failed to fetch latest release from GitHub", exc_info=True)
        return None


def fetch_latest_version(timeout: float = 3.0) -> str | None:
    """Return the latest released version, or ``None`` when unknown.

    Tries PyPI first (canonical for ``pip``-installed users). Falls back to
    GitHub Releases when PyPI returns nothing — this is the only signal
    available to frozen binaries and to environments where the package was
    never published to PyPI.

    Returns ``None`` only when both sources fail; callers should treat that
    as *unknown* and proceed without blocking the audit.
    """
    return _fetch_pypi_latest(timeout) or _fetch_github_latest(timeout)


def is_newer(latest: str, current: str) -> bool:
    """Return ``True`` when *latest* is strictly newer than *current*.

    Uses ``packaging.version.Version`` for PEP 440 compliance, with a
    naive tuple-split fallback when the ``packaging`` library is absent.
    """
    try:
        from packaging.version import Version
        return Version(latest) > Version(current)
    except Exception:
        # Fallback: simple tuple comparison for "X.Y.Z" versions
        try:
            def _parts(v: str) -> tuple[int, ...]:
                return tuple(int(x) for x in v.split("."))
            return _parts(latest) > _parts(current)
        except (ValueError, TypeError):
            return False


# ------------------------------------------------------------------
# Editable-install detection
# ------------------------------------------------------------------

def is_editable_install() -> bool:
    """Return ``True`` when the package was installed in editable mode."""
    try:
        from importlib.metadata import distribution
        dist = distribution(_PYPI_PACKAGE)
        raw = dist.read_text("direct_url.json")
        if raw:
            data = json.loads(raw)
            return data.get("dir_info", {}).get("editable", False)
    except Exception:
        pass
    return False


# ------------------------------------------------------------------
# Update execution
# ------------------------------------------------------------------

def _find_project_root() -> Path:
    """Locate the project root for editable installs."""
    import gws_auditor
    # __init__.py is at src/gws_auditor/__init__.py → up 3 levels
    return Path(gws_auditor.__file__).resolve().parent.parent.parent


def perform_update(editable: bool = False) -> bool:
    """Run ``pip install`` to upgrade the package.

    Returns ``True`` on success (exit code 0).
    """
    cmd = [sys.executable, "-m", "pip", "install"]
    if editable:
        cmd.extend(["-e", str(_find_project_root())])
    else:
        cmd.extend(["--upgrade", _PYPI_PACKAGE])

    result = subprocess.run(cmd)
    return result.returncode == 0


# ------------------------------------------------------------------
# Interactive prompt
# ------------------------------------------------------------------

def prompt_for_update(current: str, latest: str, frozen: bool = False) -> bool:
    """Display an update-available banner and ask the user to confirm.

    Returns ``False`` without prompting when stdin is not a TTY
    (e.g. CI pipelines, piped input). Returns ``False`` for frozen
    (PyInstaller) builds because in-place ``pip`` upgrade is not possible
    \u2014 the banner directs the user to the GitHub releases page instead.
    """
    try:
        from rich.console import Console
        console = Console(stderr=True)
    except ImportError:
        console = None

    msg = (
        f"A new version of gws-auditor is available: "
        f"{current} \u2192 {latest}"
    )

    if console:
        console.print(f"\n[bold yellow]{msg}[/bold yellow]")
    else:
        print(f"\n{msg}", file=sys.stderr)

    if frozen:
        hint = f"Download the new binary from {_GITHUB_RELEASES_PAGE}"
        if console:
            console.print(f"[dim]{hint}[/dim]\n")
        else:
            print(hint, file=sys.stderr)
        return False

    if not sys.stdin.isatty():
        hint = "Run 'gws-auditor --update' to upgrade."
        if console:
            console.print(f"[dim]{hint}[/dim]\n")
        else:
            print(hint, file=sys.stderr)
        return False

    try:
        from rich.prompt import Confirm
        return Confirm.ask("Update now?", default=False)
    except ImportError:
        answer = input("Update now? [y/N]: ").strip().lower()
        return answer in ("y", "yes")


# ------------------------------------------------------------------
# High-level orchestrators
# ------------------------------------------------------------------

def check_and_prompt_update(skip: bool = False, quiet: bool = False) -> None:
    """Non-blocking startup check for a newer version.

    Called early in ``main()`` before config loading.  Swallows all
    exceptions so it can never prevent the audit from running.

    Parameters
    ----------
    skip:
        When ``True`` (set by ``--skip-update-check``), return immediately.
    quiet:
        When ``True`` (set by ``--quiet``), print the notice but do not
        prompt interactively.
    """
    try:
        if skip:
            return

        from ._frozen import is_frozen
        frozen = is_frozen()

        current = get_installed_version()
        latest = fetch_latest_version()
        if latest is None or not is_newer(latest, current):
            return

        if quiet:
            if frozen:
                print(
                    f"gws-auditor {latest} is available (you have {current}). "
                    f"Download from {_GITHUB_RELEASES_PAGE}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"gws-auditor {latest} is available (you have {current}). "
                    f"Run 'gws-auditor --update' to upgrade.",
                    file=sys.stderr,
                )
            return

        if prompt_for_update(current, latest, frozen=frozen):
            editable = is_editable_install()
            success = perform_update(editable)
            if success:
                print(
                    f"\nUpdated to {latest}. "
                    "Please re-run your command.",
                    file=sys.stderr,
                )
                sys.exit(0)
            else:
                print(
                    "\nUpdate failed. You can retry manually with:\n"
                    f"  pip install --upgrade {_PYPI_PACKAGE}",
                    file=sys.stderr,
                )
    except SystemExit:
        raise  # Allow sys.exit(0) after successful update
    except Exception:
        logger.debug("Version check failed", exc_info=True)


def run_update_only() -> int:
    """Perform the update without running an audit.

    Returns an exit code: 0 on success, 1 on failure.

    For frozen (PyInstaller) builds, ``pip install --upgrade`` cannot
    replace the running binary, so the function reports the version
    delta and directs the user to the GitHub releases page rather than
    attempting an in-place upgrade.
    """
    from ._frozen import is_frozen
    frozen = is_frozen()

    current = get_installed_version()
    latest = fetch_latest_version(timeout=10.0)

    if latest is None:
        print(
            "Could not determine the latest version. "
            "Check your network connection or visit "
            f"{_GITHUB_RELEASES_PAGE} manually.",
            file=sys.stderr,
        )
        return 1

    if not is_newer(latest, current):
        print(f"gws-auditor {current} is already the latest version.")
        return 0

    if frozen:
        print(
            f"A new version of gws-auditor is available: {current} \u2192 {latest}\n"
            f"This is a standalone executable; in-place upgrade is not supported.\n"
            f"Download the new binary from:\n  {_GITHUB_RELEASES_PAGE}",
            file=sys.stderr,
        )
        return 0

    print(f"Updating gws-auditor: {current} \u2192 {latest}")
    editable = is_editable_install()
    success = perform_update(editable)

    if success:
        print(f"Successfully updated to {latest}.")
        return 0
    else:
        print(
            f"Update failed. You can retry manually with:\n"
            f"  pip install --upgrade {_PYPI_PACKAGE}",
            file=sys.stderr,
        )
        return 1
