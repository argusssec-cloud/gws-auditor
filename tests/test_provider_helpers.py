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
