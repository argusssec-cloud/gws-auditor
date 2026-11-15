"""Guard against checks that read Policy API fields which do not exist.

A whole class of false FAIL / false PASS bugs came from checks reading invented field
names (e.g. ``allowUnconfiguredThirdPartyApps`` instead of ``accessLevel``) while their
unit tests used the same invented names, so everything stayed green.

``tests/fixtures/policy_api_shapes.json`` lists the setting types and field names the
Cloud Identity Policy API really returns. For every check function that looks up a known
setting type via ``get_ou_values(<category>, "<setting_key>")``, this test requires the
function to reference at least one real field of that setting type.
"""

import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKS_DIR = ROOT / "src" / "gws_auditor" / "checks"
SHAPES = json.loads((Path(__file__).parent / "fixtures" / "policy_api_shapes.json").read_text())["settings"]

# setting key (the part after "<category>.") -> union of real field names
FIELDS_BY_KEY: dict[str, set[str]] = {}
for _type, _fields in SHAPES.items():
    _key = _type.split(".", 1)[1]
    FIELDS_BY_KEY.setdefault(_key, set()).update(f.split("[].")[-1] for f in _fields)

# (function, setting key) pairs that are deliberate. Keep this list short and justified.
EXEMPT: dict[tuple[str, str], str] = {
    ("check_flagged_email_action", "spam_override_lists"): "legacy-shape fallback; real type email_attachment_safety is read first",
    ("check_drive_add_ons_disabled", "drive_sdk"): "legacy-shape fallback; add-ons are not in the Policy API (admin-log inference is used)",
    ("check_meet_auto_transcription", "video_recording"): "legacy-shape fallback; API exposes only enableRecording, so the result is MANUAL",
    ("check_context_aware_access", "login_challenges"): "legacy-shape fallback; CAA is not in the Policy API (TOGGLE_CAA_ENABLEMENT log event is used)",
    ("check_gmail_comprehensive_storage", "comprehensive_mail_storage"): "API returns only a ruleId; the check reports MANUAL when no enabled flag exists",
}


def _strings(node) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _setting_keys(func) -> set[str]:
    """Setting keys a function looks up: string args of get_ou_values() or of a private helper."""
    keys = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "")
            if name == "get_ou_values" or name.startswith("_"):
                keys |= {a.value for a in node.args
                         if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value in FIELDS_BY_KEY}
    return keys


def _is_check(func) -> bool:
    return any(getattr(getattr(d, "func", d), "id", "") == "check" for d in func.decorator_list)


def _cases():
    for path in sorted(CHECKS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        # Module-level helpers and constants a check may read its setting keys / field names through
        strings: dict[str, set[str]] = {}
        keys: dict[str, set[str]] = {}
        refs: dict[str, set[str]] = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                strings[node.name], keys[node.name] = _strings(node), _setting_keys(node)
                refs[node.name] = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        strings[target.id], keys[target.id], refs[target.id] = _strings(node.value), set(), set()
        for func in (n for n in tree.body if isinstance(n, ast.FunctionDef) and _is_check(n)):
            seen, todo = set(), [func.name]
            while todo:  # transitive closure over helpers/constants defined in this module
                name = todo.pop()
                if name in seen or name not in strings:
                    continue
                seen.add(name)
                todo.extend(refs[name])
            all_strings = set().union(*(strings[n] for n in seen))
            for key in sorted(set().union(*(keys[n] for n in seen))):
                if (func.name, key) not in EXEMPT:
                    yield pytest.param(path.name, func.name, key, all_strings, id=f"{path.stem}.{func.name}[{key}]")


@pytest.mark.parametrize("module, func, key, strings", list(_cases()))
def test_check_reads_a_real_field(module, func, key, strings):
    real = FIELDS_BY_KEY[key]
    assert strings & real, (
        f"{module}:{func} looks up setting '{key}' but references none of its real Policy API "
        f"fields {sorted(real)}. It is probably reading an invented field name."
    )


def test_exemptions_still_exist():
    """An exemption for a function/key that no longer exists should be removed."""
    live = set()
    for path in CHECKS_DIR.glob("*.py"):
        for func in (n for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef)):
            for node in ast.walk(func):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "get_ou_values"
                        and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
                    live.add((func.name, node.args[1].value))
    assert set(EXEMPT) <= live, f"stale exemptions: {sorted(set(EXEMPT) - live)}"


def test_catalogue_is_not_empty():
    assert len(SHAPES) > 50
    assert "accessLevel" in FIELDS_BY_KEY["unconfigured_third_party_apps"]
