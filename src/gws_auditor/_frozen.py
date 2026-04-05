# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Utilities for running as a PyInstaller-frozen executable."""

import sys
from pathlib import Path


def is_frozen() -> bool:
    """Return True when running inside a PyInstaller bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def resolve_package_path(anchor_file: str) -> Path:
    """Resolve the directory of *anchor_file* in both normal and frozen mode.

    In normal mode, returns ``Path(anchor_file).resolve().parent``.
    In frozen mode (PyInstaller ``--onefile``), returns the equivalent
    path inside the temporary extraction directory (``sys._MEIPASS``).

    Usage in a module::

        _DIR = resolve_package_path(__file__)
        template_dir = _DIR / "templates"
    """
    if is_frozen():
        base = Path(sys._MEIPASS)
        resolved = Path(anchor_file).resolve()
        # In frozen mode, __file__ resolves inside sys._MEIPASS
        try:
            rel = resolved.relative_to(base)
            return base / rel.parent
        except ValueError:
            pass
        # Fallback: the file is already inside _MEIPASS, use its parent
        return resolved.parent
    return Path(anchor_file).resolve().parent
