"""Unit tests for provider helper functions."""

import pytest

from gws_auditor.provider import (
    _dual_case_keys,
    _parse_duration_seconds,
    _to_camel_case,
    _to_snake_case,
)


class TestToSnakeCase:
    """Tests for _to_snake_case()."""

    def test_camel_case(self):
        assert _to_snake_case("camelCase") == "camel_case"

    def test_pascal_case(self):
        assert _to_snake_case("PascalCase") == "pascal_case"

    def test_already_snake(self):
        assert _to_snake_case("already_snake") == "already_snake"

    def test_acronym_prefix(self):
        assert _to_snake_case("HTMLParser") == "html_parser"

    def test_acronym_suffix(self):
        assert _to_snake_case("simpleURL") == "simple_url"

    def test_empty_string(self):
        assert _to_snake_case("") == ""

    def test_single_word(self):
        assert _to_snake_case("single") == "single"

    def test_multiple_caps(self):
        assert _to_snake_case("enableSMTPAccess") == "enable_smtp_access"


class TestToCamelCase:
    """Tests for _to_camel_case()."""

    def test_snake_case(self):
        assert _to_camel_case("snake_case") == "snakeCase"

    def test_multi_part_snake(self):
        assert _to_camel_case("already_camel") == "alreadyCamel"

    def test_single_word(self):
        assert _to_camel_case("single") == "single"

    def test_empty_string(self):
        assert _to_camel_case("") == ""

    def test_three_parts(self):
        assert _to_camel_case("one_two_three") == "oneTwoThree"


class TestDualCaseKeys:
    """Tests for _dual_case_keys()."""

    def test_adds_snake_from_camel(self):
        d = {"camelCase": 1}
        result = _dual_case_keys(d)
        assert result["camel_case"] == 1
        assert result["camelCase"] == 1

    def test_adds_camel_from_snake(self):
        d = {"snake_case": 2}
        result = _dual_case_keys(d)
        assert result["snakeCase"] == 2
        assert result["snake_case"] == 2

    def test_no_duplicate_when_both_exist(self):
        d = {"already_there": 3, "alreadyThere": 4}
        result = _dual_case_keys(d)
        # Both originals preserved, no overwrite
        assert result["already_there"] == 3
        assert result["alreadyThere"] == 4

    def test_empty_dict(self):
        d = {}
        result = _dual_case_keys(d)
        assert result == {}

    def test_mutates_in_place(self):
        d = {"fooBar": 5}
        result = _dual_case_keys(d)
        assert result is d

    def test_single_word_key_unchanged(self):
        d = {"simple": 10}
        result = _dual_case_keys(d)
        # single word is both snake and camel already
        assert result == {"simple": 10}


class TestParseDurationSeconds:
    """Tests for _parse_duration_seconds()."""

    def test_normal_duration(self):
        assert _parse_duration_seconds("1209600s") == 1209600

    def test_zero(self):
        assert _parse_duration_seconds("0s") == 0

    def test_with_whitespace(self):
        assert _parse_duration_seconds("  3600s ") == 3600

    def test_missing_suffix(self):
        assert _parse_duration_seconds("3600") == 3600

    def test_empty_string(self):
        assert _parse_duration_seconds("") == 0

    def test_none(self):
        assert _parse_duration_seconds(None) == 0

    def test_float_string(self):
        assert _parse_duration_seconds("3600.5s") == 3600

    def test_malformed(self):
        assert _parse_duration_seconds("abcs") == 0

    def test_very_large(self):
        assert _parse_duration_seconds("999999999s") == 999999999

    def test_small_value(self):
        assert _parse_duration_seconds("1s") == 1


class TestTrustRulesLoading:
    """Drive trust rules have no read API, so they are loaded from a
    JSON file named by options.trust_rules_file — on live runs and on
    --cached re-scoring alike."""

    RULES = [
        {
            "displayName": "Block partner sharing",
            "status": "ACTIVE",
            "trigger": ["DRIVE_SHARE_TRUST"],
            "targets": {"includedEntity": [{"ouId": "03ph8a2z1"}]},
            "action": [{"actionName": "BLOCK_SHARE"}],
        }
    ]

    def _cache_file(self, tmp_path):
        import json
        cache = tmp_path / "audit.json"
        cache.write_text(json.dumps({"users": [], "policies": {}}))
        return str(cache)

    def _rules_file(self, tmp_path, content=None):
        import json
        f = tmp_path / "trust_rules.json"
        f.write_text(json.dumps(self.RULES if content is None else content))
        return str(f)

    def test_from_cache_loads_trust_rules(self, tmp_path):
        from gws_auditor.provider import Provider

        config = {"options": {"trust_rules_file": self._rules_file(tmp_path)}}
        data = Provider.from_cache(self._cache_file(tmp_path), config)
        assert data["policies"]["drive"]["trust_rules"] == self.RULES

    def test_from_cache_without_config_has_no_rules(self, tmp_path):
        from gws_auditor.provider import Provider

        data = Provider.from_cache(self._cache_file(tmp_path))
        assert "trust_rules" not in data.get("policies", {}).get("drive", {})

    def test_unset_option_loads_nothing(self, tmp_path):
        from gws_auditor.provider import Provider

        data = Provider.from_cache(self._cache_file(tmp_path), {"options": {}})
        assert "trust_rules" not in data.get("policies", {}).get("drive", {})

    def test_missing_file_is_tolerated(self, tmp_path):
        from gws_auditor.provider import Provider

        config = {"options": {"trust_rules_file": str(tmp_path / "nope.json")}}
        data = Provider.from_cache(self._cache_file(tmp_path), config)
        assert "trust_rules" not in data.get("policies", {}).get("drive", {})

    def test_non_list_json_rejected(self, tmp_path):
        from gws_auditor.provider import Provider

        config = {
            "options": {
                "trust_rules_file": self._rules_file(tmp_path, {"not": "a list"}),
            }
        }
        data = Provider.from_cache(self._cache_file(tmp_path), config)
        assert "trust_rules" not in data.get("policies", {}).get("drive", {})

    def test_malformed_json_is_tolerated(self, tmp_path):
        from gws_auditor.provider import Provider

        f = tmp_path / "broken.json"
        f.write_text("{not json")
        config = {"options": {"trust_rules_file": str(f)}}
        data = Provider.from_cache(self._cache_file(tmp_path), config)
        assert "trust_rules" not in data.get("policies", {}).get("drive", {})

    def test_loader_returns_rules_directly(self, tmp_path):
        from gws_auditor.provider import Provider

        config = {"options": {"trust_rules_file": self._rules_file(tmp_path)}}
        assert Provider._load_trust_rules_from_file(config) == self.RULES
