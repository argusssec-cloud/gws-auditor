# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section agent registry — maps section names to check/test module paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class SectionMapping:
    """Maps a section name to its check module and test module."""
    section: str
    check_modules: list[str]
    test_modules: list[str]
    check_id_prefixes: list[str]


# Master registry of all sections and their source files.
# Paths are relative to the project's src/gws_auditor/checks/ directory.
SECTION_REGISTRY: dict[str, SectionMapping] = {
    "Google Chat": SectionMapping(
        section="Google Chat",
        check_modules=["apps_chat.py"],
        test_modules=["test_chat.py"],
        check_id_prefixes=["CIS-3.1.4"],
    ),
    "Gmail": SectionMapping(
        section="Gmail",
        check_modules=["apps_gmail.py"],
        test_modules=["test_gmail.py"],
        check_id_prefixes=["CIS-3.1.3"],
    ),
    "Drive": SectionMapping(
        section="Drive",
        check_modules=["apps_drive.py"],
        test_modules=["test_drive.py"],
        check_id_prefixes=["CIS-3.1.2"],
    ),
    "Calendar": SectionMapping(
        section="Calendar",
        check_modules=["apps_calendar.py"],
        test_modules=["test_calendar.py"],
        check_id_prefixes=["CIS-3.1.1"],
    ),
    "Directory": SectionMapping(
        section="Directory",
        check_modules=["directory.py"],
        test_modules=["test_directory.py"],
        check_id_prefixes=["CIS-1"],
    ),
    "Groups": SectionMapping(
        section="Groups",
        check_modules=["apps_groups.py"],
        test_modules=["test_groups.py"],
        check_id_prefixes=["CIS-3.1.6"],
    ),
    "Sites": SectionMapping(
        section="Sites",
        check_modules=["apps_sites.py"],
        test_modules=["test_sites.py"],
        check_id_prefixes=["CIS-3.1.7"],
    ),
    "Marketplace": SectionMapping(
        section="Marketplace",
        check_modules=["apps_marketplace.py"],
        test_modules=["test_marketplace.py"],
        check_id_prefixes=["CIS-3.1.9"],
    ),
    "Security": SectionMapping(
        section="Security",
        check_modules=["security_auth.py", "security_access.py"],
        test_modules=["test_security_auth.py", "test_security_access.py"],
        check_id_prefixes=["CIS-4.1", "CIS-4.2"],
    ),
    "Reporting": SectionMapping(
        section="Reporting",
        check_modules=["reporting.py", "rules.py"],
        test_modules=[],
        check_id_prefixes=["CIS-5", "CIS-6"],
    ),
    "CISA": SectionMapping(
        section="CISA",
        check_modules=[
            "cisa_scuba.py",
            "cisa_commoncontrols.py",
            "cisa_services.py",
        ],
        test_modules=[
            "test_cisa_scuba.py",
            "test_cisa_commoncontrols.py",
            "test_cisa_services.py",
        ],
        check_id_prefixes=["GWS."],
    ),
    "Additional": SectionMapping(
        section="Additional",
        check_modules=["additional.py"],
        test_modules=["test_additional.py"],
        check_id_prefixes=["ADD-"],
    ),
}


def get_section_names() -> list[str]:
    """Return all registered section names."""
    return list(SECTION_REGISTRY.keys())


def resolve_paths(
    section: str,
    checks_dir: Path,
    tests_dir: Path,
) -> tuple[list[Path], list[Path]]:
    """Resolve check and test module paths for a section.

    Returns:
        (check_paths, test_paths) — lists of resolved Path objects.
        Missing files are included in the list but may not exist on disk.
    """
    mapping = SECTION_REGISTRY.get(section)
    if mapping is None:
        return [], []

    check_paths = [checks_dir / m for m in mapping.check_modules]
    test_paths = [tests_dir / m for m in mapping.test_modules]
    return check_paths, test_paths
