# Contributing to GWS Security Auditor

Thank you for your interest in contributing to GWS Security Auditor! This guide covers how to set up a development environment, add security checks, write tests, and submit changes.

## Getting Started

### Prerequisites

- Python 3.9+
- A Google Workspace tenant for testing (a free Cloud Identity account works for development)
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/argusssec-cloud/gws-auditor.git
cd gws-auditor

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Verify installation
pytest
gws-auditor --help
```

### Optional Dependencies

```bash
pip install -e ".[dashboard]"    # Plotly Dash dashboard
pip install -e ".[ai]"           # AI security analyst (all providers)
pip install -e ".[build]"        # PyInstaller standalone builds
```

## Project Structure

```
src/gws_auditor/
  api/           # Google API client wrappers
  checks/        # Security check modules (decorator-registered)
  ai/            # AI analyst (tools, providers, commands)
  dashboard/     # Plotly Dash web UI
  reporter/      # Output generation (HTML, JSON, CSV)
tests/
  test_checks/   # Check-specific tests
  test_api/      # API client tests
  test_ai/       # AI analyst tests
```

## Adding a New Security Check

Every check is a decorated function. The `@check` decorator auto-registers it.

### Step 1: Write the Check

Add your check function to the appropriate module in `src/gws_auditor/checks/`:

```python
from .base import check, make_pass, make_fail, make_warn

@check(
    check_id="ADD-40",                # Unique ID
    title="Ensure feature X is configured",
    level="L1",                        # L1 (essential) or L2 (defence-in-depth)
    source="OTHER",                    # CIS, CISA, GOOGLE, or OTHER
    section="Security",                # Logical grouping
    remediation=(
        "Admin console > Security > Feature X. Enable the setting. "
        "https://knowledge.workspace.google.com/admin/security/feature-x"
    ),
    requires_license="",               # Optional: business_standard, enterprise_plus, etc.
)
def check_feature_x(data: dict) -> CheckResult:
    """Feature X should be configured for security."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    feature_x = security.get("feature_x_enabled")

    if feature_x is True:
        return make_pass(
            check_id="ADD-40",
            title="Ensure feature X is configured",
            level="L1", source="OTHER", section="Security",
            details="Feature X is enabled.",
            actual_value=feature_x,
            expected_value=True,
        )

    return make_fail(
        check_id="ADD-40",
        title="Ensure feature X is configured",
        level="L1", source="OTHER", section="Security",
        details="Feature X is not enabled.",
        actual_value=feature_x,
        expected_value=True,
        remediation=(
            "Admin console > Security > Feature X. Enable the setting. "
            "https://knowledge.workspace.google.com/admin/security/feature-x"
        ),
    )
```

### Step 2: Add Tests

Create tests in `tests/test_checks/` following the existing pattern:

```python
class TestFeatureX:
    def test_pass_enabled(self, full_audit_data):
        from gws_auditor.checks.additional import check_feature_x
        full_audit_data["policies"]["security"]["feature_x_enabled"] = True
        result = check_feature_x(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_disabled(self, full_audit_data):
        from gws_auditor.checks.additional import check_feature_x
        full_audit_data["policies"]["security"]["feature_x_enabled"] = False
        result = check_feature_x(full_audit_data)
        assert result.status == Status.FAIL
```

### Step 3: Run Tests

```bash
pytest tests/test_checks/ -x -v
```

### Check ID Conventions

- **CIS checks**: `CIS-X.Y.Z` (maps to CIS Benchmark section numbers)
- **CISA SCuBA checks**: `GWS.SERVICE.X.Y` (e.g., `GWS.GMAIL.4.3`)
- **Additional checks**: `ADD-XX` (sequential numbering, currently up to ADD-39)

### Check Helpers

| Function | When to Use |
|----------|-------------|
| `make_pass(...)` | Check condition is met |
| `make_fail(...)` | Check condition is NOT met |
| `make_warn(...)` | Partially met or non-blocking issue |
| `make_manual(...)` | Cannot determine automatically (API error) |
| `make_review(...)` | Requires human judgment |

### License-Gated Checks

If a feature requires a specific Google Workspace edition, use `requires_license`:

```python
@check(
    ...
    requires_license="enterprise_standard",  # or business_standard, enterprise_plus, etc.
)
```

The check auto-returns `NOT_APPLICABLE` on lower-tier tenants. Valid tiers (lowest to highest): `business_starter`, `business_standard`, `business_plus`, `enterprise_standard`, `enterprise_plus`, `assured_controls`.

### Remediation Text

Always include:
1. **Admin Console navigation path** (e.g., "Admin console > Security > 2SV")
2. **Documentation URL** from `https://knowledge.workspace.google.com/admin/...`

## Adding an AI Analyst Tool

Tools are defined in `src/gws_auditor/ai/tools.py`:

1. Add the JSON Schema definition to `TOOL_DEFINITIONS`
2. Add the executor function (prefix with `_`)
3. Add the dispatch branch in `execute_tool()`
4. Add tests in `tests/test_ai/test_tools.py`

## Adding a Slash Command

Commands are registered in `src/gws_auditor/ai/commands.py` via the `@command` decorator:

```python
@command("/mycommand", "Description of what it does", category="Skills")
def cmd_mycommand(session, console, args, ctx):
    _stream_prompt(session, console, "Your crafted prompt here")
    return None
```

## Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_checks/test_gmail.py

# With coverage
pytest --cov=gws_auditor --cov-report=term-missing

# Skip agent tests (requires pydantic_ai)
pytest --ignore=tests/test_agents
```

## Code Style

- Follow existing patterns in the codebase
- Use type hints for function signatures
- Keep check functions focused -- one check per function
- Use `logger.info()` for significant events, `logger.debug()` for internals
- Copyright header on every new Python file:

```python
# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/add-check-xyz`
3. Make your changes
4. Run the full test suite: `pytest`
5. Commit with a descriptive message
6. Open a Pull Request against `main`

### PR Checklist

- [ ] New checks have tests covering pass, fail, and edge cases
- [ ] Remediation text includes Admin Console path and documentation URL
- [ ] `requires_license` is set if the feature needs a specific edition
- [ ] All tests pass (`pytest`)
- [ ] No secrets, credentials, or internal data in the commit

## Reporting Issues

- Use [GitHub Issues](https://github.com/argusssec-cloud/gws-auditor/issues)
- Include the error message and stack trace
- Specify your Python version and Google Workspace edition
- For check-specific issues, include the check ID and expected vs actual behavior

## Questions?

Open a [Discussion](https://github.com/argusssec-cloud/gws-auditor/discussions) or reach out via Issues.
