# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Shared fixtures for agent tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from gws_auditor.ai.agents.deps import CheckDeps
from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckFix,
    CheckIssue,
    Severity,
    TestCase,
)

# Resolve project root paths
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_CHECKS_DIR = _PROJECT_ROOT / "src" / "gws_auditor" / "checks"
_TESTS_DIR = _PROJECT_ROOT / "tests" / "test_checks"
_BASE_HELPERS = _CHECKS_DIR / "base.py"
_CONFTEST = _PROJECT_ROOT / "tests" / "conftest.py"


def _read_if_exists(p: Path) -> str:
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


@pytest.fixture
def project_root() -> Path:
    return _PROJECT_ROOT


@pytest.fixture
def checks_dir() -> Path:
    return _CHECKS_DIR


@pytest.fixture
def chat_check_source() -> str:
    return _read_if_exists(_CHECKS_DIR / "apps_chat.py")


@pytest.fixture
def chat_test_source() -> str:
    return _read_if_exists(_TESTS_DIR / "test_chat.py")


@pytest.fixture
def security_auth_source() -> str:
    return _read_if_exists(_CHECKS_DIR / "security_auth.py")


@pytest.fixture
def security_access_source() -> str:
    return _read_if_exists(_CHECKS_DIR / "security_access.py")


@pytest.fixture
def gmail_check_source() -> str:
    return _read_if_exists(_CHECKS_DIR / "apps_gmail.py")


@pytest.fixture
def cisa_services_source() -> str:
    return _read_if_exists(_CHECKS_DIR / "cisa_services.py")


@pytest.fixture
def base_helpers_source() -> str:
    return _read_if_exists(_BASE_HELPERS)


@pytest.fixture
def conftest_source() -> str:
    return _read_if_exists(_CONFTEST)


@pytest.fixture
def chat_deps(
    chat_check_source, chat_test_source, base_helpers_source, conftest_source
) -> CheckDeps:
    """CheckDeps for the Google Chat section."""
    return CheckDeps(
        check_source_code=chat_check_source,
        test_source_code=chat_test_source,
        module_path=str(_CHECKS_DIR / "apps_chat.py"),
        check_ids=[
            "CIS-3.1.4.1.1",
            "CIS-3.1.4.1.2",
            "CIS-3.1.4.2.1",
            "CIS-3.1.4.3.1",
            "CIS-3.1.4.4.1",
            "CIS-3.1.4.4.2",
        ],
        benchmark_requirements={
            "CIS-3.1.4.1.1": "Ensure external chat is restricted",
            "CIS-3.1.4.1.2": "Ensure external file sharing in chat is disabled",
            "CIS-3.1.4.2.1": (
                "If external chat is allowed, ensure a domain allowlist is "
                "configured with at least one domain"
            ),
            "CIS-3.1.4.3.1": "Ensure chat history is enabled",
            "CIS-3.1.4.4.1": "Ensure chat apps/bots installation is restricted",
            "CIS-3.1.4.4.2": "Ensure incoming webhooks are disabled",
        },
        base_helpers_source=base_helpers_source,
        conftest_source=conftest_source,
    )


@pytest.fixture
def security_deps(
    security_auth_source, security_access_source, base_helpers_source, conftest_source
) -> CheckDeps:
    """CheckDeps for the Security section (auth + access)."""
    combined_source = security_auth_source + "\n\n" + security_access_source
    return CheckDeps(
        check_source_code=combined_source,
        test_source_code="",
        module_path=str(_CHECKS_DIR / "security_auth.py"),
        check_ids=[
            "CIS-4.1.1.1",
            "CIS-4.2.1.2",
            "CIS-4.2.1.4",
            "CIS-4.2.3.1",
        ],
        benchmark_requirements={
            "CIS-4.1.1.1": "Ensure admin accounts have logged in recently",
            "CIS-4.2.1.2": (
                "Ensure third-party OAuth app access is reviewed and restricted"
            ),
            "CIS-4.2.1.4": (
                "Ensure domain-wide delegation is not granted or is reviewed"
            ),
            "CIS-4.2.3.1": "Ensure DLP rules are properly configured",
        },
        base_helpers_source=base_helpers_source,
        conftest_source=conftest_source,
    )


@pytest.fixture
def sample_analysis() -> CheckAnalysis:
    """A sample CheckAnalysis for testing."""
    return CheckAnalysis(
        module_name="apps_chat",
        section="Google Chat",
        total_checks_analyzed=6,
        issues=[
            CheckIssue(
                check_id="CIS-3.1.4.2.1",
                severity=Severity.CRITICAL,
                category=BugCategory.FALSE_POSITIVE,
                description="len(allowed_domains) >= 0 always true",
                benchmark_requirement="Domain allowlist must have entries",
                current_behavior="Always passes due to >= 0",
                correct_behavior="Should use > 0",
            ),
        ],
        fixes=[
            CheckFix(
                check_id="CIS-3.1.4.2.1",
                function_name="check_chat_external_domain_allowlist",
                fixed_code="def check(): len(x) > 0",
                explanation="Changed >= to >",
            ),
        ],
        test_cases=[
            TestCase(
                test_name="test_empty_allowlist_fails",
                test_class="TestChatChecks",
                test_code="def test_empty_allowlist_fails(): ...",
                is_regression=True,
            ),
        ],
        summary="Found 1 critical issue",
    )
