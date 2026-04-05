# Standalone Build

Build a single-file executable that runs without Python installed.

## Build from Source

```bash
# Install build dependency
pip install -e ".[build]"

# Build single-file executable (~90 MB)
python build.py

# Build one-directory bundle (faster startup)
python build.py --onedir

# Clean previous builds first
python build.py --clean
```

Output: `dist/gws-auditor` (Linux) or `dist/gws-auditor.exe` (Windows).

## Pre-built Binaries

Download from the [Releases](../../releases) page:

| Platform | Filename |
|----------|----------|
| Linux x86_64 | `gws-auditor-linux-amd64` |
| Windows x86_64 | `gws-auditor-windows-amd64.exe` |

### Running

Standalone binaries don't include a `config.yaml`, so you must pass authentication arguments on the command line:

```bash
# Minimum required arguments
./gws-auditor-linux-amd64 --credentials credentials.json --subject admin@yourdomain.com

# With optional flags
./gws-auditor-linux-amd64 --credentials credentials.json --subject admin@yourdomain.com --customer-id C0abc123 -v
```

> **Note:** `--subject` (super-admin email for domain-wide delegation) is required when no `config.yaml` is present. Without it, all API calls will fail with permission errors.

## How It Works

The build uses [PyInstaller](https://pyinstaller.org/) with a custom spec file (`gws-auditor.spec`) that:

- Auto-discovers all 16+ check modules (decorator-registered)
- Bundles Jinja2 HTML report templates
- Bundles dashboard CSS/JS assets
- Handles frozen-mode path resolution via `_frozen.py`
- Excludes heavy optional dependencies (tkinter, matplotlib, numpy)

## CI/CD Automated Builds

Push a git tag `v*` to trigger `.github/workflows/build-executable.yml`:

1. Builds on `ubuntu-20.04` (Linux) and `windows-latest`
2. Runs tests first
3. Smoke-tests the executable
4. Attaches binaries to the GitHub release

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## Compatibility

| Platform | Requirement |
|----------|-------------|
| Linux | glibc 2.29+ (Ubuntu 20.04+, CentOS 8+) |
| Windows | Windows 10+ with Visual C++ Redistributable |
