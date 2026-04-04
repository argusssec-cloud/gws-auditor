# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for gws-auditor standalone executable.

Build commands:
    # One-file executable (simpler distribution)
    pyinstaller gws-auditor.spec

    # One-directory bundle (faster startup)
    pyinstaller gws-auditor.spec --onedir

The spec auto-collects all check modules, templates, and assets.
"""

import os
import sys
from pathlib import Path

block_cipher = None

# Project root
ROOT = os.path.dirname(os.path.abspath(SPEC))
SRC = os.path.join(ROOT, "src")

# All check modules must be collected for decorator-based registration
check_modules = [
    f"gws_auditor.checks.{p.stem}"
    for p in Path(SRC, "gws_auditor", "checks").glob("*.py")
    if p.stem not in ("__init__", "base", "registry")
]

# Hidden imports that PyInstaller can't detect statically
hidden_imports = [
    # Check modules (decorator-registered, not imported directly)
    *check_modules,
    # Google auth transports
    "google.auth.transport.requests",
    "google.auth.transport.urllib3",
    "google.auth.transport._http_client",
    "google.auth._default",
    # Google API client internals
    "googleapiclient._helpers",
    "googleapiclient.channel",
    # httplib2 proxy support
    "httplib2.socks",
    # DNS
    "dns.resolver",
    "dns.rdatatype",
    # YAML C extension fallback
    "yaml",
    "_yaml",
    # Rich terminal
    "rich.traceback",
    "rich.logging",
]

# Data files to bundle
datas = [
    # Jinja2 HTML report template
    (
        os.path.join(SRC, "gws_auditor", "reporter", "templates"),
        os.path.join("gws_auditor", "reporter", "templates"),
    ),
    # Dashboard assets (CSS, JS)
    (
        os.path.join(SRC, "gws_auditor", "dashboard", "assets"),
        os.path.join("gws_auditor", "dashboard", "assets"),
    ),
]

# Create a wrapper script that imports and calls main() properly
_WRAPPER = os.path.join(ROOT, "build", "_gws_entry.py")
os.makedirs(os.path.dirname(_WRAPPER), exist_ok=True)
with open(_WRAPPER, "w") as _f:
    _f.write("import sys; sys.path.insert(0, ''); "
             "from gws_auditor.__main__ import main; sys.exit(main() or 0)\n")

a = Analysis(
    [_WRAPPER],
    pathex=[SRC],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy optional deps not needed for core audit
        "tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "PIL",
        "cv2",
        "IPython",
        "notebook",
        "pytest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="gws-auditor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Windows icon (optional)
    # icon="assets/icon.ico",
)
