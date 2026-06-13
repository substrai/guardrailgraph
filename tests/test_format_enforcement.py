"""Tests for output length and format enforcement check."""

import json

import pytest

from guardrailgraph.checks.format_enforcement import (
    EnforcementSeverity,
    FieldRequirement,
    FormatEnforcementCheck,
    FormatEnforcementConfig,
    FormatEnforcementResult,
    FormatViolation,
    LengthConfig,
    ViolationType,
)


@pytest.fixture
def length_checker():
    config = FormatEnforcementConfig(
        length=LengthConfig(min_length=10, max_length=100),
    )
    return FormatEnforcementCheck(config)


@pytest.fixture
def json_checker():
    config = FormatEnforcementConfig(
        require_json=True,
        required_fields=[
            FieldRequirement(path="status", field_type="str"),
            FieldRequirement(path="data", field_type="dict"),
        ],
    )
    return FormatEnforcementCheck(config)


class TestLengthEnforcement:
    def test_response_within_limits(self, length_checker):
        result = length_checker.check("This is a valid response text.")
        assert result.passed is True
        assert result.violation_count == 0
        assert result.score == 1.0

    def test_response_too_short(self, length_checker):
        result = length_checker.check("Short")
        assert result.passed is False
        assert result.violation_count == 1
        assert result.violations[0].violation_type == ViolationType.TOO_SHORT

    def test_response_too_long(self, length_checker):
        result = length_checker.check("x" * 150)
        assert result.passed is False
        assert result.violation_count == 1
        assert result.violations[0].violation_type == ViolationType.TOO_LONG

    def test_word_count_enforcement(self):
        config = FormatEnforcementConfig(
            length=LengthConfig(min_words=5, max_words=20),
        )
        checker = FormatEnforcementCheck(config)

        result = checker.check("one two")
        assert result.passed is False
        assert any(v.violation_type == ViolationType.TOO_SHORT for v in result.violations)

        result = checker.check("word " * 25)
        assert result.passed is False
        assert any(v.violation_type == ViolationType.TOO_LONG for v in result.violations)

    def test_exact_boundary_lengths(self):
        config = FormatEnforcementConfig(
            length=LengthConfig(min_length=5, max_length=10),
        )
        checker = FormatEnforcementCheck(config)

        # Exactly at min boundary
        result = checker.check("12345")
        assert result.passed is True

        # Exactly at max boundary
        result = checker.check("1234567890")
        assert result.passed is True


class TestJsonEnforcement:
    def test_valid_json_with_required_fields(self, json_checker):
        response = json.dumps({"status": "ok", "data": {"items": [1, 2, 3]}})
        result = json_checker.check(response)
        assert result.passed is True
        assert result.is_valid_json is True

    def test_invalid_json(self, json_checker):
        result = json_checker.check("not json at all")
        assert result.passed is False
        assert result.is_valid_json is False
        assert any(v.violation_type == ViolationType.INVALID_JSON for v in result.violations)

    def test_missing_required_field(self, json_checker):
        response = json.dumps({"status": "ok"})
        result = json_checker.check(response)
        assert result.passed is False
        assert any(v.violation_type == ViolationType.MISSING_FIELD for v in result.violations)

    def test_wrong_field_type(self, json_checker):
        response = json.dumps({"status": 123, "data": {}})
        result = json_checker.check(response)
        assert result.passed is False
        assert any(v.violation_type == ViolationType.WRONG_TYPE for v in result.violations)


class TestNestedFieldValidation:
    def test_nested_field_present(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="data.items", field_type="list"),
            ],
        )
        checker = FormatEnforcementCheck(config)
        response = json.dumps({"data": {"items": [1, 2, 3]}})
        result = checker.check(response)
        assert result.passed is True

    def test_nested_field_missing(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="data.items", field_type="list"),
            ],
        )
        checker = FormatEnforcementCheck(config)
        response = json.dumps({"data": {"other": "value"}})
        result = checker.check(response)
        assert result.passed is False

    def test_field_pattern_validation(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="email", field_type="str", pattern=r"^[\w.]+@[\w.]+$"),
            ],
        )
        checker = FormatEnforcementCheck(config)

        valid = json.dumps({"email": "user@example.com"})
        result = checker.check(valid)
        assert result.passed is True

        invalid = json.dumps({"email": "not-an-email"})
        result = checker.check(invalid)
        assert result.passed is False

    def test_field_allowed_values(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="status", allowed_values={"active", "inactive"}),
            ],
        )
        checker = FormatEnforcementCheck(config)

        valid = json.dumps({"status": "active"})
        result = checker.check(valid)
        assert result.passed is True

        invalid = json.dumps({"status": "deleted"})
        result = checker.check(invalid)
        assert result.passed is False


class TestScoring:
    def test_perfect_score(self):
        config = FormatEnforcementConfig(length=LengthConfig(min_length=1))
        checker = FormatEnforcementCheck(config)
        result = checker.check("Valid response")
        assert result.score == 1.0

    def test_degraded_score_with_violations(self):
        config = FormatEnforcementConfig(
            length=LengthConfig(min_length=100, max_length=200),
        )
        checker = FormatEnforcementCheck(config)
        result = checker.check("Short")
        assert result.score < 1.0
        assert result.score >= 0.0

    def test_critical_violation_heavily_penalizes(self):
        config = FormatEnforcementConfig(require_json=True)
        checker = FormatEnforcementCheck(config)
        result = checker.check("not json")
        assert result.score < 0.6  # Critical violation = 0.5 penalty


class TestConfiguration:
    def test_default_config(self):
        checker = FormatEnforcementCheck()
        result = checker.check("Any response")
        assert result.passed is True

    def test_fail_on_first_violation(self):
        config = FormatEnforcementConfig(
            length=LengthConfig(min_length=100),
            require_json=True,
            fail_on_first=True,
        )
        checker = FormatEnforcementCheck(config)
        result = checker.check("short")
        # Should stop after length violation, not check JSON
        assert result.passed is False
        assert result.violation_count == 1

    def test_optional_field_missing_is_ok(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="optional_field", required=False),
            ],
        )
        checker = FormatEnforcementCheck(config)
        response = json.dumps({"other": "value"})
        result = checker.check(response)
        assert result.passed is True

    def test_field_min_max_length(self):
        config = FormatEnforcementConfig(
            require_json=True,
            required_fields=[
                FieldRequirement(path="name", field_type="str", min_length=3, max_length=50),
            ],
        )
        checker = FormatEnforcementCheck(config)

        valid = json.dumps({"name": "John Doe"})
        result = checker.check(valid)
        assert result.passed is True

        too_short = json.dumps({"name": "Jo"})
        result = checker.check(too_short)
        assert result.passed is False
