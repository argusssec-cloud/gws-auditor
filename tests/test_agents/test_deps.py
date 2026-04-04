# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for CheckDeps dependency injection."""

from pathlib import Path

import pytest

from gws_auditor.ai.agents.deps import CheckDeps


class TestCheckDeps:
    def test_create_minimal(self):
        deps = CheckDeps(
            check_source_code="def check(): pass",
            test_source_code="def test(): pass",
            module_path="checks/apps_chat.py",
        )
        assert deps.check_source_code == "def check(): pass"
        assert deps.check_ids == []
        assert deps.benchmark_requirements == {}
        assert deps.base_helpers_source == ""
        assert deps.conftest_source == ""

    def test_create_full(self):
        deps = CheckDeps(
            check_source_code="source",
            test_source_code="tests",
            module_path="checks/apps_chat.py",
            check_ids=["CIS-3.1.4.1.1", "CIS-3.1.4.2.1"],
            benchmark_requirements={
                "CIS-3.1.4.1.1": "Restrict external chat",
                "CIS-3.1.4.2.1": "Configure domain allowlist",
            },
            base_helpers_source="def make_pass(): ...",
            conftest_source="@pytest.fixture ...",
        )
        assert len(deps.check_ids) == 2
        assert "CIS-3.1.4.2.1" in deps.benchmark_requirements

    def test_from_paths_with_real_files(self, tmp_path):
        check_file = tmp_path / "apps_chat.py"
        check_file.write_text("def check_chat(): pass\n")

        test_file = tmp_path / "test_chat.py"
        test_file.write_text("def test_chat(): assert True\n")

        base_file = tmp_path / "base.py"
        base_file.write_text("def make_pass(): ...\n")

        conftest_file = tmp_path / "conftest.py"
        conftest_file.write_text("import pytest\n")

        deps = CheckDeps.from_paths(
            check_module=check_file,
            test_module=test_file,
            base_helpers=base_file,
            conftest=conftest_file,
            check_ids=["CIS-3.1.4.1.1"],
            benchmark_requirements={"CIS-3.1.4.1.1": "restrict external chat"},
        )

        assert "def check_chat" in deps.check_source_code
        assert "def test_chat" in deps.test_source_code
        assert "def make_pass" in deps.base_helpers_source
        assert "import pytest" in deps.conftest_source
        assert deps.module_path == str(check_file)

    def test_from_paths_missing_test_file(self, tmp_path):
        check_file = tmp_path / "apps_chat.py"
        check_file.write_text("def check_chat(): pass\n")

        deps = CheckDeps.from_paths(
            check_module=check_file,
            test_module=None,
        )
        assert deps.check_source_code == "def check_chat(): pass\n"
        assert deps.test_source_code == ""

    def test_from_paths_nonexistent_file(self, tmp_path):
        check_file = tmp_path / "apps_chat.py"
        check_file.write_text("source\n")

        missing = tmp_path / "nonexistent.py"

        deps = CheckDeps.from_paths(
            check_module=check_file,
            test_module=missing,
        )
        assert deps.test_source_code == ""
