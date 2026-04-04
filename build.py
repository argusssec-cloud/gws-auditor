#!/usr/bin/env python3
"""Build standalone gws-auditor executable using PyInstaller.

Usage:
    python build.py              # Build for current platform
    python build.py --onedir     # One-directory bundle (faster startup)
    python build.py --clean      # Clean previous builds first

Requirements:
    pip install pyinstaller
"""

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC_FILE = ROOT / "gws-auditor.spec"
DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"


def main():
    parser = argparse.ArgumentParser(description="Build gws-auditor executable")
    parser.add_argument("--onedir", action="store_true",
                        help="Build as one-directory bundle instead of single file")
    parser.add_argument("--clean", action="store_true",
                        help="Clean build artifacts before building")
    parser.add_argument("--no-upx", action="store_true",
                        help="Disable UPX compression")
    args = parser.parse_args()

    # Check PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("PyInstaller not found. Install with:")
        print("  pip install pyinstaller")
        sys.exit(1)

    # Clean if requested
    if args.clean:
        print("Cleaning previous builds...")
        for d in (BUILD_DIR, DIST_DIR):
            if d.exists():
                shutil.rmtree(d)

    # Build command
    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC_FILE)]

    if args.onedir:
        # Override --onefile in spec with --onedir
        cmd.append("--noconfirm")
        print("Building one-directory bundle...")
    else:
        cmd.append("--noconfirm")
        print("Building single-file executable...")

    if args.no_upx:
        cmd.append("--noupx")

    # Run PyInstaller
    print(f"Command: {' '.join(cmd)}")
    print()
    result = subprocess.run(cmd, cwd=str(ROOT))

    if result.returncode != 0:
        print(f"\nBuild failed with exit code {result.returncode}")
        sys.exit(result.returncode)

    # Report result
    system = platform.system().lower()
    ext = ".exe" if system == "windows" else ""
    exe_path = DIST_DIR / f"gws-auditor{ext}"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\nBuild successful!")
        print(f"  Executable: {exe_path}")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"  Platform: {platform.system()} {platform.machine()}")
        print(f"\nTest with:")
        print(f"  {exe_path} --list-checks")
    else:
        # One-dir mode
        dir_path = DIST_DIR / "gws-auditor"
        if dir_path.exists():
            total = sum(f.stat().st_size for f in dir_path.rglob("*") if f.is_file())
            size_mb = total / (1024 * 1024)
            print(f"\nBuild successful!")
            print(f"  Directory: {dir_path}")
            print(f"  Total size: {size_mb:.1f} MB")
            print(f"\nTest with:")
            print(f"  {dir_path}/gws-auditor{ext} --list-checks")
        else:
            print("\nBuild completed but executable not found at expected path.")
            print(f"Check {DIST_DIR} for output.")


if __name__ == "__main__":
    main()
