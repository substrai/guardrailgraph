"""Output length and format enforcement check.

Validates response length, JSON structure, required fields presence.
Configurable min/max length, schema validation, and field requirements.

Features:
- Response length validation (min/max character count)
- JSON structure validation against schemas
- Required fields presence check
- Configurable enforcement rules with severity levels
- Support for nested field validation
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union


class EnforcementSeverity(Enum):
    """Severity level for format violations."""

    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ViolationType(Enum):
    """Types of format violations."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    INVALID_JSON = "invalid_json"
    MISSING_FIELD = "missing_field"
    WRONG_TYPE = "wrong_type"
    PATTERN_MISMATCH = "pattern_mismatch"
    INVALID_STRUCTURE = "invalid_structure"


@dataclass
class FormatViolation:
    """A single format violation found during enforcement check.

    Attributes:
        violation_type: The type of violation detected.
        message: Human-readable description of the violation.
        field_path: JSON path to the violating field (if applicable).
        expected: What was expected.
        actual: What was found.
        severity: How severe this violation is.
    """

    violation_type: ViolationType
    message: str
    field_path: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    severity: EnforcementSeverity = EnforcementSeverity.ERROR


@dataclass
class FieldRequirement:
    """Specification for a required field in the response.

    Attributes:
        path: Dot-notation path to the field (e.g., "data.items").
        field_type: Expected Python type name ("str", "int", "list", "dict", "bool", "float").
        required: Whether the field must be present.
        min_length: Minimum length for string/list fields.
        max_length: Maximum length for string/list fields.
        pattern: Regex pattern for string fields.
        allowed_values: Set of allowed values (for enum-like fields).
    """

    path: str
    field_type: Optional[str] = None
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    allowed_values: Optional[Set[str]] = None


@dataclass
class LengthConfig:
    """Configuration for response length enforcement.

    Attributes:
        min_length: Minimum allowed response length in characters.
        max_length: Maximum allowed response length in characters.
        min_words: Minimum word count.
        max_words: Maximum word count.
        count_whitespace: Whether to include whitespace in length count.
    """

    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_words: Optional[int] = None
    max_words: Optional[int] = None
    count_whitespace: bool = True


@dataclass
class FormatEnforcementConfig:
    """Configuration for the format enforcement check.

    Attributes:
        length: Length enforcement configuration.
        require_json: Whether the response must be valid JSON.
        json_schema: Optional JSON schema-like dict for validation.
        required_fields: List of field requirements for JSON responses.
        severity: Default severity for violations.
        fail_on_first: Whether to stop checking after first violation.
    """

    length: LengthConfig = field(default_factory=LengthConfig)
    require_json: bool = False
    json_schema: Optional[Dict[str, Any]] = None
    required_fields: List[FieldRequirement] = field(default_factory=list)
    severity: EnforcementSeverity = EnforcementSeverity.ERROR
    fail_on_first: bool = False


@dataclass
class FormatEnforcementResult:
    """Result of a format enforcement check.

    Attributes:
        passed: Whether all checks passed.
        violations: List of format violations found.
        response_length: Actual response length in characters.
        word_count: Actual word count.
        is_valid_json: Whether the response is valid JSON.
        parsed_json: Parsed JSON object (if valid JSON).
        score: Compliance score from 0.0 to 1.0.
    """

    passed: bool = True
    violations: List[FormatViolation] = field(default_factory=list)
    response_length: int = 0
    word_count: int = 0
    is_valid_json: bool = False
    parsed_json: Optional[Any] = None
    score: float = 1.0

    @property
    def violation_count(self) -> int:
        """Number of violations found."""
        return len(self.violations)

    @property
    def critical_violations(self) -> List[FormatViolation]:
        """Get only critical violations."""
        return [v for v in self.violations if v.severity == EnforcementSeverity.CRITICAL]

    @property
    def error_violations(self) -> List[FormatViolation]:
        """Get only error-level violations."""
        return [v for v in self.violations if v.severity == EnforcementSeverity.ERROR]


class FormatEnforcementCheck:
    """Validates response format, length, and structure.

    Performs configurable validation of LLM responses including
    length checks, JSON validation, and required field verification.

    Args:
        config: Format enforcement configuration.

    Example:
        config = FormatEnforcementConfig(
            length=LengthConfig(min_length=10, max_length=1000),
            require_json=True,
            required_fields=[
                FieldRequirement(path="status", field_type="str"),
                FieldRequirement(path="data.items", field_type="list"),
            ],
        )
        checker = FormatEnforcementCheck(config)
        result = checker.check(response_text)
    """

    def __init__(self, config: Optional[FormatEnforcementConfig] = None):
        self.config = config or FormatEnforcementConfig()

    def check(self, response: str) -> FormatEnforcementResult:
        """Run all configured format enforcement checks.

        Args:
            response: The LLM response text to validate.

        Returns:
            FormatEnforcementResult with check outcomes.
        """
        result = FormatEnforcementResult()

        # Measure response
        result.response_length = self._measure_length(response)
        result.word_count = self._count_words(response)

        # Length checks
        self._check_length(response, result)

        if self.config.fail_on_first and result.violations:
            result.passed = False
            result.score = 0.0
            return result

        # JSON checks
        if self.config.require_json:
            self._check_json(response, result)

            if self.config.fail_on_first and result.violations:
                result.passed = False
                result.score = 0.0
                return result

        # Field requirements (only if JSON is valid)
        if result.is_valid_json and self.config.required_fields:
            self._check_required_fields(result)

        # Calculate score
        result.passed = len(result.violations) == 0
        result.score = self._calculate_score(result)

        return result

    def _measure_length(self, response: str) -> int:
        """Measure response length based on config."""
        if self.config.length.count_whitespace:
            return len(response)
        return len(response.replace(" ", "").replace("\n", "").replace("\t", ""))

    def _count_words(self, response: str) -> int:
        """Count words in the response."""
        return len(response.split())

    def _check_length(self, response: str, result: FormatEnforcementResult) -> None:
        """Check response length constraints."""
        length = result.response_length
        word_count = result.word_count

        if self.config.length.min_length is not None and length < self.config.length.min_length:
            result.violations.append(FormatViolation(
                violation_type=ViolationType.TOO_SHORT,
                message=f"Response too short: {length} chars (minimum: {self.config.length.min_length})",
                expected=f">= {self.config.length.min_length} chars",
                actual=f"{length} chars",
                severity=self.config.severity,
            ))

        if self.config.length.max_length is not None and length > self.config.length.max_length:
            result.violations.append(FormatViolation(
                violation_type=ViolationType.TOO_LONG,
                message=f"Response too long: {length} chars (maximum: {self.config.length.max_length})",
                expected=f"<= {self.config.length.max_length} chars",
                actual=f"{length} chars",
                severity=self.config.severity,
            ))

        if self.config.length.min_words is not None and word_count < self.config.length.min_words:
            result.violations.append(FormatViolation(
                violation_type=ViolationType.TOO_SHORT,
                message=f"Response too few words: {word_count} (minimum: {self.config.length.min_words})",
                expected=f">= {self.config.length.min_words} words",
                actual=f"{word_count} words",
                severity=self.config.severity,
            ))

        if self.config.length.max_words is not None and word_count > self.config.length.max_words:
            result.violations.append(FormatViolation(
                violation_type=ViolationType.TOO_LONG,
                message=f"Response too many words: {word_count} (maximum: {self.config.length.max_words})",
                expected=f"<= {self.config.length.max_words} words",
                actual=f"{word_count} words",
                severity=self.config.severity,
            ))

    def _check_json(self, response: str, result: FormatEnforcementResult) -> None:
        """Check if response is valid JSON."""
        try:
            parsed = json.loads(response)
            result.is_valid_json = True
            result.parsed_json = parsed
        except (json.JSONDecodeError, ValueError) as e:
            result.is_valid_json = False
            result.violations.append(FormatViolation(
                violation_type=ViolationType.INVALID_JSON,
                message=f"Response is not valid JSON: {str(e)}",
                severity=EnforcementSeverity.CRITICAL,
            ))

    def _check_required_fields(self, result: FormatEnforcementResult) -> None:
        """Check required fields in parsed JSON."""
        if result.parsed_json is None:
            return

        for field_req in self.config.required_fields:
            self._validate_field(result.parsed_json, field_req, result)

    def _validate_field(
        self,
        data: Any,
        field_req: FieldRequirement,
        result: FormatEnforcementResult,
    ) -> None:
        """Validate a single field requirement."""
        value = self._get_nested_value(data, field_req.path)

        # Check presence
        if value is None:
            if field_req.required:
                result.violations.append(FormatViolation(
                    violation_type=ViolationType.MISSING_FIELD,
                    message=f"Required field missing: '{field_req.path}'",
                    field_path=field_req.path,
                    expected="field present",
                    actual="field missing",
                    severity=self.config.severity,
                ))
            return

        # Check type
        if field_req.field_type:
            if not self._check_type(value, field_req.field_type):
                result.violations.append(FormatViolation(
                    violation_type=ViolationType.WRONG_TYPE,
                    message=f"Field '{field_req.path}' has wrong type: expected {field_req.field_type}, got {type(value).__name__}",
                    field_path=field_req.path,
                    expected=field_req.field_type,
                    actual=type(value).__name__,
                    severity=self.config.severity,
                ))
                return

        # Check min/max length for strings and lists
        if field_req.min_length is not None and hasattr(value, "__len__"):
            if len(value) < field_req.min_length:
                result.violations.append(FormatViolation(
                    violation_type=ViolationType.TOO_SHORT,
                    message=f"Field '{field_req.path}' too short: {len(value)} (min: {field_req.min_length})",
                    field_path=field_req.path,
                    severity=self.config.severity,
                ))

        if field_req.max_length is not None and hasattr(value, "__len__"):
            if len(value) > field_req.max_length:
                result.violations.append(FormatViolation(
                    violation_type=ViolationType.TOO_LONG,
                    message=f"Field '{field_req.path}' too long: {len(value)} (max: {field_req.max_length})",
                    field_path=field_req.path,
                    severity=self.config.severity,
                ))

        # Check pattern for strings
        if field_req.pattern and isinstance(value, str):
            if not re.match(field_req.pattern, value):
                result.violations.append(FormatViolation(
                    violation_type=ViolationType.PATTERN_MISMATCH,
                    message=f"Field '{field_req.path}' does not match pattern: {field_req.pattern}",
                    field_path=field_req.path,
                    expected=field_req.pattern,
                    actual=value,
                    severity=self.config.severity,
                ))

        # Check allowed values
        if field_req.allowed_values and str(value) not in field_req.allowed_values:
            result.violations.append(FormatViolation(
                violation_type=ViolationType.PATTERN_MISMATCH,
                message=f"Field '{field_req.path}' value not allowed: '{value}'",
                field_path=field_req.path,
                expected=f"one of {field_req.allowed_values}",
                actual=str(value),
                severity=self.config.severity,
            ))

    def _get_nested_value(self, data: Any, path: str) -> Any:
        """Get a nested value from a dict using dot notation."""
        parts = path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if a value matches the expected type string."""
        type_map = {
            "str": str,
            "string": str,
            "int": int,
            "integer": int,
            "float": float,
            "number": (int, float),
            "bool": bool,
            "boolean": bool,
            "list": list,
            "array": list,
            "dict": dict,
            "object": dict,
        }
        expected = type_map.get(expected_type.lower())
        if expected is None:
            return True  # Unknown type, skip check
        return isinstance(value, expected)

    def _calculate_score(self, result: FormatEnforcementResult) -> float:
        """Calculate compliance score based on violations."""
        if not result.violations:
            return 1.0

        severity_weights = {
            EnforcementSeverity.WARNING: 0.1,
            EnforcementSeverity.ERROR: 0.3,
            EnforcementSeverity.CRITICAL: 0.5,
        }

        total_penalty = sum(
            severity_weights.get(v.severity, 0.3) for v in result.violations
        )

        return max(0.0, 1.0 - total_penalty)
