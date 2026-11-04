"""Layer 0 contract gates from the check-correctness test plan (kept outside the repo, in ~/workspace_security).

These guard the two defect classes the field-name test cannot see:

* a check that looks up a Policy API setting type the API never returns (its OU branch is
  dead code, so the check silently falls back or goes MANUAL in production);
* a synthetic ``GOOGLE_DEFAULTS`` entry whose field names are not real API fields (checks
  reading the real field see nothing, checks reading the invented one judge fiction).

Both gates carry an exemption list that enumerates the violations known on 2026-11-01 so
the gate passes now and fails on any new one. Each exemption must be resolved in plan
phase P3 (implement on a real setting type, or declare MANUAL-by-design and unscored).
"""

import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKS_DIR = ROOT / "src" / "gws_auditor" / "checks"
SHAPES = json.loads((Path(__file__).parent / "fixtures" / "policy_api_shapes.json").read_text())["settings"]
KNOWN_KEYS = {t.split(".", 1)[1] for t in SHAPES}
MATRIX = json.loads((Path(__file__).parent / "fixtures" / "check_test_matrix.json").read_text())

# (check function, setting key) -> why it is still looked up although the API never returns it.
DEAD_SETTING_KEYS: dict[tuple[str, str], str] = {}  # all resolved in plan phase P3

# GOOGLE_DEFAULTS setting type -> invented field names tolerated until P0 decides the defaults policy.
DEFAULTS_WITH_INVENTED_FIELDS: dict[str, set[str]] = {}


def _lookups():
    """Yield (module, function, setting key) for every get_ou_values() literal key in the checks."""
    for path in sorted(CHECKS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for func in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
            for node in ast.walk(func):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "get_ou_values"
                        and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
                    yield path.name, func.name, node.args[1].value


class TestSettingKeysExist:
    def test_every_looked_up_setting_type_is_real(self):
        unknown = sorted({(f, k) for _, f, k in _lookups() if k not in KNOWN_KEYS and (f, k) not in DEAD_SETTING_KEYS})
        assert not unknown, (
            "get_ou_values() keys that the Policy API never returns (see policy_api_shapes.json): "
            f"{unknown}. Use the real setting type, or add a justified DEAD_SETTING_KEYS entry.")

    def test_dead_key_exemptions_are_live(self):
        live = {(f, k) for _, f, k in _lookups()}
        stale = sorted(set(DEAD_SETTING_KEYS) - live)
        assert not stale, f"DEAD_SETTING_KEYS entries no longer present in the code: {stale}"

    def test_dead_key_exemptions_are_still_unknown(self):
        resolved = sorted(k for (_, k) in DEAD_SETTING_KEYS if k in KNOWN_KEYS)
        assert not resolved, f"catalogue now knows these keys; drop their exemptions: {resolved}"


class TestGoogleDefaultsUseRealFields:
    def test_default_values_only_use_catalogue_fields(self):
        from gws_auditor.api.policy import GOOGLE_DEFAULTS

        bad = {}
        for setting_type, value in GOOGLE_DEFAULTS.items():
            assert setting_type in SHAPES, f"GOOGLE_DEFAULTS has unknown setting type {setting_type}"
            real = {f.split("[].")[-1] for f in SHAPES[setting_type]}
            invented = set(value) - real - DEFAULTS_WITH_INVENTED_FIELDS.get(setting_type, set())
            if invented:
                bad[setting_type] = sorted(invented)
        assert not bad, f"GOOGLE_DEFAULTS fields the Policy API does not have: {bad}"

    def test_invented_field_exemptions_are_live(self):
        from gws_auditor.api.policy import GOOGLE_DEFAULTS

        for setting_type, fields in DEFAULTS_WITH_INVENTED_FIELDS.items():
            assert fields <= set(GOOGLE_DEFAULTS.get(setting_type, {})), (
                f"exemption for {setting_type} {sorted(fields)} is stale")


class TestMatrixCoversRegistry:
    def test_matrix_has_one_row_per_registered_check(self):
        from gws_auditor.checks.registry import CheckRegistry

        registered = {m.check_id for m in CheckRegistry().get_all_checks()}
        in_matrix = {row["check_id"] for row in MATRIX}
        assert registered - in_matrix == set(), f"checks missing from check_test_matrix.json: {sorted(registered - in_matrix)}"
        assert in_matrix - registered == set(), f"matrix rows for unregistered checks: {sorted(in_matrix - registered)}"

    @pytest.mark.parametrize("field", ["pass_case", "fail_case", "other_cases", "edge_cases"])
    def test_every_row_has_the_required_cases(self, field):
        empty = [row["check_id"] for row in MATRIX if not str(row.get(field, "")).strip()]
        assert not empty, f"matrix rows with empty {field}: {empty}"


class TestSystemPoliciesAreJudged:
    """Decision A: a SYSTEM policy is the value in force and must be judged, so no check may
    drop it with admin_only=True. The decorator adds the provenance note instead."""

    def test_no_check_filters_out_system_policies(self):
        offenders = []
        for path in sorted(CHECKS_DIR.glob("*.py")):
            if path.name == "base.py":
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if "admin_only=True" in line:
                    offenders.append(f"{path.name}:{lineno}")
        assert not offenders, f"checks still discard SYSTEM policies: {offenders}"

    def test_injected_defaults_are_documented(self):
        from gws_auditor.api.policy import GOOGLE_DEFAULTS
        from gws_auditor.google_defaults import ALL_DEFAULTS

        for setting_type, value in GOOGLE_DEFAULTS.items():
            assert ALL_DEFAULTS.get(setting_type) == value, setting_type

    def test_documented_defaults_use_catalogue_fields(self):
        from gws_auditor.google_defaults import ALL_DEFAULTS

        bad = {}
        for setting_type, fields in ALL_DEFAULTS.items():
            if setting_type not in SHAPES:
                continue  # documented by Google, never observed live; nothing reads it yet
            real = {f.split("[].")[-1] for f in SHAPES[setting_type]}
            invented = sorted(set(fields) - real)
            if invented:
                bad[setting_type] = invented
        assert not bad, bad
