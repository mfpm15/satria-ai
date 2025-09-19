"""
SATRIA AI OCSF Schema Validator and Normalizer
Ensures all events conform to Open Cybersecurity Schema Framework standards
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime
from enum import Enum
import re

from satria.models.events import BaseEvent, EventCategory, EventClass, Severity, Confidence
from satria.core.config import settings


class ValidationResult(Enum):
    """Validation result status"""
    VALID = "valid"
    WARNING = "warning"
    ERROR = "error"


class ValidationIssue:
    """Validation issue details"""

    def __init__(self, level: ValidationResult, field: str, message: str, suggestion: Optional[str] = None):
        self.level = level
        self.field = field
        self.message = message
        self.suggestion = suggestion
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "field": self.field,
            "message": self.message,
            "suggestion": self.suggestion,
            "timestamp": self.timestamp.isoformat()
        }


class OCSFValidator:
    """OCSF Schema Validator"""

    def __init__(self):
        self.logger = logging.getLogger("satria.schema.validator")
        self.validation_rules = self._load_validation_rules()

        # Quality thresholds
        self.min_quality_score = 0.7
        self.warning_quality_score = 0.8

    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load OCSF validation rules"""
        return {
            "required_fields": {
                "base": ["event_type", "event_category", "event_class", "timestamp", "source_agent"],
                "finding": ["severity", "confidence", "entities"],
                "network": ["source_ip", "destination_ip"],
                "process": ["process_name", "command_line"],
                "authentication": ["user_id", "result"]
            },
            "field_patterns": {
                "ip_address": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                "hash_md5": r"^[a-fA-F0-9]{32}$",
                "hash_sha1": r"^[a-fA-F0-9]{40}$",
                "hash_sha256": r"^[a-fA-F0-9]{64}$",
                "domain": r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
                "url": r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?$"
            },
            "severity_mappings": {
                "0": Severity.INFORMATIONAL,
                "1": Severity.LOW,
                "2": Severity.MEDIUM,
                "3": Severity.HIGH,
                "4": Severity.CRITICAL,
                "info": Severity.INFORMATIONAL,
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL
            }
        }

    def validate_event(self, event_data: Union[Dict[str, Any], BaseEvent]) -> Tuple[ValidationResult, List[ValidationIssue], float]:
        """
        Validate event against OCSF schema
        Returns: (overall_result, issues_list, quality_score)
        """
        issues = []

        # Convert to dict if BaseEvent
        if isinstance(event_data, BaseEvent):
            data = event_data.dict()
        else:
            data = event_data.copy()

        # Basic structure validation
        issues.extend(self._validate_basic_structure(data))

        # Required fields validation
        issues.extend(self._validate_required_fields(data))

        # Data type validation
        issues.extend(self._validate_data_types(data))

        # Format validation
        issues.extend(self._validate_formats(data))

        # Entity validation
        issues.extend(self._validate_entities(data.get("entities", [])))

        # Evidence validation
        issues.extend(self._validate_evidence(data.get("evidence", [])))

        # MITRE ATT&CK validation
        issues.extend(self._validate_attack_techniques(data.get("attack_techniques", [])))

        # Calculate quality score
        quality_score = self._calculate_quality_score(data, issues)

        # Determine overall result
        overall_result = self._determine_overall_result(issues, quality_score)

        return overall_result, issues, quality_score

    def _validate_basic_structure(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate basic event structure"""
        issues = []

        # Check if event_id exists and is valid UUID format
        if "event_id" not in data:
            issues.append(ValidationIssue(
                ValidationResult.WARNING,
                "event_id",
                "Missing event_id, will be auto-generated",
                "Add unique event_id for better traceability"
            ))
        elif not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', str(data["event_id"]), re.IGNORECASE):
            issues.append(ValidationIssue(
                ValidationResult.WARNING,
                "event_id",
                "event_id does not match UUID format",
                "Use standard UUID format for event_id"
            ))

        # Validate timestamp
        if "timestamp" in data:
            try:
                if isinstance(data["timestamp"], str):
                    datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                issues.append(ValidationIssue(
                    ValidationResult.ERROR,
                    "timestamp",
                    "Invalid timestamp format",
                    "Use ISO 8601 format: YYYY-MM-DDTHH:MM:SS.fffffZ"
                ))

        return issues

    def _validate_required_fields(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate required fields based on event type"""
        issues = []

        # Base required fields
        for field in self.validation_rules["required_fields"]["base"]:
            if field not in data or data[field] is None:
                issues.append(ValidationIssue(
                    ValidationResult.ERROR,
                    field,
                    f"Required field '{field}' is missing",
                    f"Add '{field}' to event data"
                ))

        # Category-specific required fields
        event_category = data.get("event_category")
        if event_category == EventCategory.FINDINGS:
            for field in self.validation_rules["required_fields"]["finding"]:
                if field not in data or data[field] is None:
                    issues.append(ValidationIssue(
                        ValidationResult.ERROR,
                        field,
                        f"Required field '{field}' for findings events is missing",
                        f"Add '{field}' for proper finding classification"
                    ))

        return issues

    def _validate_data_types(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate data types"""
        issues = []

        type_checks = {
            "risk_score": (int, float),
            "confidence": str,
            "quality_score": (int, float),
            "entities": list,
            "evidence": list,
            "attack_techniques": list,
            "recommendations": list
        }

        for field, expected_type in type_checks.items():
            if field in data and data[field] is not None:
                if not isinstance(data[field], expected_type):
                    issues.append(ValidationIssue(
                        ValidationResult.ERROR,
                        field,
                        f"Field '{field}' has incorrect type, expected {expected_type}",
                        f"Convert '{field}' to correct type"
                    ))

        return issues

    def _validate_formats(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate field formats using regex patterns"""
        issues = []

        format_checks = [
            ("source_ip", "ip_address"),
            ("destination_ip", "ip_address"),
            ("sender", "email"),
            ("domain", "domain"),
            ("url", "url")
        ]

        for field, pattern_name in format_checks:
            if field in data and data[field]:
                pattern = self.validation_rules["field_patterns"].get(pattern_name)
                if pattern and not re.match(pattern, str(data[field])):
                    issues.append(ValidationIssue(
                        ValidationResult.WARNING,
                        field,
                        f"Field '{field}' format may be invalid",
                        f"Verify '{field}' matches expected format"
                    ))

        return issues

    def _validate_entities(self, entities: List[Dict[str, Any]]) -> List[ValidationIssue]:
        """Validate entity objects"""
        issues = []

        required_entity_fields = ["entity_id", "entity_type", "name"]

        for i, entity in enumerate(entities):
            for field in required_entity_fields:
                if field not in entity:
                    issues.append(ValidationIssue(
                        ValidationResult.ERROR,
                        f"entities[{i}].{field}",
                        f"Entity missing required field '{field}'",
                        f"Add '{field}' to entity"
                    ))

        return issues

    def _validate_evidence(self, evidence_list: List[Dict[str, Any]]) -> List[ValidationIssue]:
        """Validate evidence objects"""
        issues = []

        required_evidence_fields = ["source", "value"]

        for i, evidence in enumerate(evidence_list):
            for field in required_evidence_fields:
                if field not in evidence:
                    issues.append(ValidationIssue(
                        ValidationResult.WARNING,
                        f"evidence[{i}].{field}",
                        f"Evidence missing field '{field}'",
                        f"Add '{field}' to strengthen evidence"
                    ))

        return issues

    def _validate_attack_techniques(self, techniques: List[Dict[str, Any]]) -> List[ValidationIssue]:
        """Validate MITRE ATT&CK technique objects"""
        issues = []

        technique_pattern = r'^T\d{4}(\.\d{3})?$'

        for i, technique in enumerate(techniques):
            if "technique_id" in technique:
                if not re.match(technique_pattern, technique["technique_id"]):
                    issues.append(ValidationIssue(
                        ValidationResult.WARNING,
                        f"attack_techniques[{i}].technique_id",
                        f"Invalid MITRE ATT&CK technique ID format",
                        "Use format T#### or T####.### for technique IDs"
                    ))

        return issues

    def _calculate_quality_score(self, data: Dict[str, Any], issues: List[ValidationIssue]) -> float:
        """Calculate data quality score (0.0 - 1.0)"""
        base_score = 1.0

        # Penalize for issues
        error_penalty = 0.2
        warning_penalty = 0.05

        for issue in issues:
            if issue.level == ValidationResult.ERROR:
                base_score -= error_penalty
            elif issue.level == ValidationResult.WARNING:
                base_score -= warning_penalty

        # Bonus for enrichment
        enrichment_bonus = 0.1
        enrichment_fields = ["entities", "evidence", "attack_techniques", "enrichment"]

        for field in enrichment_fields:
            if field in data and data[field]:
                base_score += enrichment_bonus / len(enrichment_fields)

        # Ensure score is between 0.0 and 1.0
        return max(0.0, min(1.0, base_score))

    def _determine_overall_result(self, issues: List[ValidationIssue], quality_score: float) -> ValidationResult:
        """Determine overall validation result"""
        # Check for errors
        if any(issue.level == ValidationResult.ERROR for issue in issues):
            return ValidationResult.ERROR

        # Check quality score
        if quality_score < self.min_quality_score:
            return ValidationResult.ERROR
        elif quality_score < self.warning_quality_score:
            return ValidationResult.WARNING

        # Check for warnings
        if any(issue.level == ValidationResult.WARNING for issue in issues):
            return ValidationResult.WARNING

        return ValidationResult.VALID


class EventNormalizer:
    """Event data normalizer to OCSF format"""

    def __init__(self):
        self.logger = logging.getLogger("satria.schema.normalizer")
        self.validator = OCSFValidator()

    def normalize_event(self, raw_data: Dict[str, Any], source_format: str = "generic") -> BaseEvent:
        """
        Normalize raw event data to OCSF BaseEvent format
        """
        try:
            # Apply format-specific normalization
            normalized = self._apply_format_normalization(raw_data, source_format)

            # Enrich with defaults
            enriched = self._enrich_with_defaults(normalized)

            # Validate and calculate quality score
            result, issues, quality_score = self.validator.validate_event(enriched)

            # Add quality metadata
            enriched["quality_score"] = quality_score
            enriched["needs_review"] = result == ValidationResult.ERROR
            enriched["validation_issues"] = [issue.to_dict() for issue in issues]

            # Create BaseEvent object
            return BaseEvent(**enriched)

        except Exception as e:
            self.logger.error(f"Error normalizing event: {e}")

            # Return minimal event with error info
            return BaseEvent(
                event_type="normalization_error",
                event_category=EventCategory.SYSTEM_ACTIVITY,
                event_class=EventClass.PROCESS_ACTIVITY,
                source_agent="normalizer",
                quality_score=0.0,
                needs_review=True,
                enrichment={"error": str(e), "raw_data": raw_data}
            )

    def _apply_format_normalization(self, data: Dict[str, Any], source_format: str) -> Dict[str, Any]:
        """Apply format-specific normalization rules"""
        normalized = data.copy()

        if source_format == "syslog":
            normalized = self._normalize_syslog(normalized)
        elif source_format == "windows_event":
            normalized = self._normalize_windows_event(normalized)
        elif source_format == "elastic_ecs":
            normalized = self._normalize_ecs(normalized)
        elif source_format == "json":
            normalized = self._normalize_json(normalized)

        return normalized

    def _normalize_syslog(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize syslog format"""
        normalized = {}

        # Map common syslog fields
        field_mappings = {
            "host": "source_host",
            "program": "process_name",
            "message": "message",
            "facility": "facility",
            "severity": "severity",
            "timestamp": "timestamp"
        }

        for syslog_field, ocsf_field in field_mappings.items():
            if syslog_field in data:
                normalized[ocsf_field] = data[syslog_field]

        # Set event classification
        normalized["event_category"] = EventCategory.SYSTEM_ACTIVITY
        normalized["event_class"] = EventClass.PROCESS_ACTIVITY

        return normalized

    def _normalize_windows_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Windows Event Log format"""
        normalized = {}

        # Map Windows Event fields
        field_mappings = {
            "EventID": "event_id",
            "Computer": "source_host",
            "TimeCreated": "timestamp",
            "Level": "severity",
            "EventRecordID": "record_id"
        }

        for win_field, ocsf_field in field_mappings.items():
            if win_field in data:
                normalized[ocsf_field] = data[win_field]

        # Determine event category based on EventID
        event_id = data.get("EventID")
        if event_id in [4624, 4625, 4634]:  # Logon events
            normalized["event_category"] = EventCategory.IDENTITY_ACCESS_MANAGEMENT
            normalized["event_class"] = EventClass.AUTHENTICATION
        else:
            normalized["event_category"] = EventCategory.SYSTEM_ACTIVITY
            normalized["event_class"] = EventClass.PROCESS_ACTIVITY

        return normalized

    def _normalize_ecs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Elastic Common Schema format"""
        normalized = data.copy()

        # ECS is already well-structured, minimal mapping needed
        ecs_mappings = {
            "@timestamp": "timestamp",
            "host.name": "source_host",
            "user.name": "user_id",
            "event.action": "event_type",
            "event.category": "event_category"
        }

        for ecs_field, ocsf_field in ecs_mappings.items():
            if ecs_field in data:
                normalized[ocsf_field] = data[ecs_field]

        return normalized

    def _normalize_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize generic JSON format"""
        normalized = data.copy()

        # Try to infer structure from common field names
        common_mappings = {
            "time": "timestamp",
            "datetime": "timestamp",
            "ts": "timestamp",
            "host": "source_host",
            "hostname": "source_host",
            "user": "user_id",
            "username": "user_id",
            "src_ip": "source_ip",
            "dst_ip": "destination_ip",
            "severity": "severity",
            "level": "severity"
        }

        for common_field, ocsf_field in common_mappings.items():
            if common_field in data and ocsf_field not in normalized:
                normalized[ocsf_field] = data[common_field]

        return normalized

    def _enrich_with_defaults(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with default values"""
        enriched = data.copy()

        # Set defaults for missing required fields
        defaults = {
            "timestamp": datetime.utcnow(),
            "event_category": EventCategory.SYSTEM_ACTIVITY,
            "event_class": EventClass.PROCESS_ACTIVITY,
            "severity": Severity.INFORMATIONAL,
            "confidence": Confidence.MEDIUM,
            "entities": [],
            "evidence": [],
            "attack_techniques": [],
            "recommendations": [],
            "enrichment": {}
        }

        for field, default_value in defaults.items():
            if field not in enriched:
                enriched[field] = default_value

        return enriched


# Global instances
validator = OCSFValidator()
normalizer = EventNormalizer()