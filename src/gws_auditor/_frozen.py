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
        # In frozen mode, __file__ is relative to sys._MEIPASS
        base = Path(sys._MEIPASS)
        # Reconstruct the relative path from the package root
        rel = Path(anchor_file).resolve().relative_to(Path.cwd())
        frozen_path = base / rel.parent
        if frozen_path.exists():
            return frozen_path
        # Fallback: try the anchor file's parent directly
        return Path(anchor_file).resolve().parent
    return Path(anchor_file).resolve().parent
