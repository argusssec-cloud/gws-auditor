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


# ------------------------------------------------------------------
# Version helpers
# ------------------------------------------------------------------

def get_installed_version() -> str:
    """Return the currently installed version string."""
    from . import __version__
    return __version__


def fetch_latest_version(timeout: float = 3.0) -> str | None:
    """Query PyPI for the latest release version.

    Returns ``None`` when the network is unreachable, the response is
    malformed, or any other error occurs — the caller should treat
    ``None`` as *unknown* and proceed without blocking the audit.
    """
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

def prompt_for_update(current: str, latest: str) -> bool:
    """Display an update-available banner and ask the user to confirm.

    Returns ``False`` without prompting when stdin is not a TTY
    (e.g. CI pipelines, piped input).
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
        from ._frozen import is_frozen
        if is_frozen():
            return
        if skip:
            return

        current = get_installed_version()
        latest = fetch_latest_version()
        if latest is None or not is_newer(latest, current):
            return

        if quiet:
            print(
                f"gws-auditor {latest} is available (you have {current}). "
                f"Run 'gws-auditor --update' to upgrade.",
                file=sys.stderr,
            )
            return

        if prompt_for_update(current, latest):
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
    """
    from ._frozen import is_frozen
    if is_frozen():
        print(
            "This is a standalone executable. Updates must be downloaded "
            "from the releases page.",
            file=sys.stderr,
        )
        return 1

    current = get_installed_version()
    latest = fetch_latest_version(timeout=10.0)

    if latest is None:
        print(
            "Could not reach PyPI to check for updates. "
            "Check your network connection.",
            file=sys.stderr,
        )
        return 1

    if not is_newer(latest, current):
        print(f"gws-auditor {current} is already the latest version.")
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
