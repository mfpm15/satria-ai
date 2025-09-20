"""
SATRIA AI Purple Team Validation Engine
Real-time red-blue team collaboration and security control validation
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class TeamRole(str, Enum):
    """Team roles in purple team exercise"""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_LEAD = "purple_lead"
    OBSERVER = "observer"
    WHITE_TEAM = "white_team"  # Exercise control


class ExercisePhase(str, Enum):
    """Purple team exercise phases"""
    PLANNING = "planning"
    PREPARATION = "preparation"
    EXECUTION = "execution"
    VALIDATION = "validation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    REMEDIATION = "remediation"


class AttackVector(str, Enum):
    """Attack vectors for validation"""
    EMAIL_PHISHING = "email_phishing"
    MALWARE_EXECUTION = "malware_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    COMMAND_CONTROL = "command_control"
    CREDENTIAL_THEFT = "credential_theft"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL_ACCESS = "physical_access"


class ValidationResult(str, Enum):
    """Validation test results"""
    DETECTED = "detected"
    MISSED = "missed"
    FALSE_POSITIVE = "false_positive"
    PARTIALLY_DETECTED = "partially_detected"
    BLOCKED = "blocked"
    DELAYED_DETECTION = "delayed_detection"


@dataclass
class AttackScenario:
    """Attack scenario definition"""
    scenario_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    attack_vector: AttackVector = AttackVector.EMAIL_PHISHING
    mitre_techniques: List[str] = field(default_factory=list)
    target_systems: List[str] = field(default_factory=list)
    difficulty_level: str = "medium"  # low, medium, high, advanced
    expected_detection_time: int = 300  # seconds
    success_criteria: List[str] = field(default_factory=list)
    validation_points: List[str] = field(default_factory=list)
    estimated_duration: int = 3600  # seconds
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class ValidationTest:
    """Individual validation test"""
    test_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scenario: AttackScenario
    phase: ExercisePhase
    red_team_action: str = ""
    expected_blue_response: str = ""
    actual_blue_response: str = ""
    detection_time: Optional[int] = None
    response_time: Optional[int] = None
    result: ValidationResult = ValidationResult.MISSED
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PurpleTeamExercise:
    """Complete purple team exercise"""
    exercise_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    objectives: List[str] = field(default_factory=list)
    scope: str = ""
    scenarios: List[AttackScenario] = field(default_factory=list)
    participants: Dict[TeamRole, List[str]] = field(default_factory=dict)

    # Exercise timeline
    planned_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    planned_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=8))
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None

    # Results
    validation_tests: List[ValidationTest] = field(default_factory=list)
    overall_score: float = 0.0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    response_effectiveness: float = 0.0

    # Status
    current_phase: ExercisePhase = ExercisePhase.PLANNING
    status: str = "planned"  # planned, active, paused, completed, cancelled
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TeamPerformanceMetrics:
    """Team performance metrics"""
    team_role: TeamRole
    exercise_id: str
    detection_accuracy: float = 0.0
    response_time_avg: float = 0.0
    false_positive_rate: float = 0.0
    collaboration_score: float = 0.0
    improvement_areas: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)


class PurpleTeamValidator(BaseAgent):
    """
    Purple Team Validation Engine
    Real-time red-blue team collaboration and security control validation
    """

    def __init__(self):
        super().__init__(
            name="purple_team_validator",
            description="Purple team validation and collaboration engine",
            version="4.0.0"
        )

        self.active_exercises: Dict[str, PurpleTeamExercise] = {}
        self.exercise_history: List[PurpleTeamExercise] = []
        self.scenario_library: Dict[str, AttackScenario] = {}
        self.team_metrics: Dict[str, TeamPerformanceMetrics] = {}

        # Real-time collaboration
        self.active_tests: Dict[str, ValidationTest] = {}
        self.team_communications: List[Dict[str, Any]] = []

        # Validation rules
        self.validation_rules: Dict[str, Dict[str, Any]] = {}

    async def initialize(self) -> bool:
        """Initialize purple team validator"""
        try:
            # Load attack scenario library
            await self._load_scenario_library()

            # Initialize validation rules
            await self._initialize_validation_rules()

            # Setup collaboration channels
            await self._setup_collaboration_channels()

            logging.info("Purple Team Validator initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Purple Team Validator: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for purple team validation"""
        try:
            validation_events = []

            # Check if event is part of active exercise
            if await self._is_exercise_event(event):
                test_result = await self._validate_blue_team_response(event)
                if test_result:
                    validation_event = await self._create_validation_event(event, test_result)
                    validation_events.append(validation_event)

            # Check for collaboration opportunities
            collaboration_insight = await self._analyze_collaboration_opportunity(event)
            if collaboration_insight:
                collab_event = await self._create_collaboration_event(event, collaboration_insight)
                validation_events.append(collab_event)

            return [event] + validation_events

        except Exception as e:
            logging.error(f"Error processing event for purple team validation: {e}")
            return [event]

    async def start_purple_team_exercise(self, exercise_name: str, scenarios: List[str],
                                       participants: Dict[TeamRole, List[str]],
                                       duration_hours: int = 8) -> PurpleTeamExercise:
        """Start new purple team exercise"""
        try:
            # Create exercise
            exercise = PurpleTeamExercise(
                name=exercise_name,
                description=f"Purple team validation exercise: {exercise_name}",
                objectives=[
                    "Validate detection capabilities",
                    "Test response procedures",
                    "Improve team collaboration",
                    "Identify security gaps"
                ],
                scope="Enterprise security controls",
                participants=participants,
                planned_end=datetime.now(timezone.utc) + timedelta(hours=duration_hours)
            )

            # Load scenarios
            for scenario_id in scenarios:
                if scenario_id in self.scenario_library:
                    exercise.scenarios.append(self.scenario_library[scenario_id])

            # Start exercise
            exercise.actual_start = datetime.now(timezone.utc)
            exercise.status = "active"
            exercise.current_phase = ExercisePhase.EXECUTION

            self.active_exercises[exercise.exercise_id] = exercise

            # Initialize validation tests
            await self._initialize_exercise_tests(exercise)

            # Notify teams
            await self._notify_exercise_start(exercise)

            logging.info(f"Started purple team exercise: {exercise.exercise_id}")

            return exercise

        except Exception as e:
            logging.error(f"Error starting purple team exercise: {e}")
            raise

    async def execute_red_team_action(self, exercise_id: str, scenario_id: str, action: str,
                                    target: str, technique: str) -> Dict[str, Any]:
        """Execute red team action and start validation"""
        try:
            exercise = self.active_exercises.get(exercise_id)
            if not exercise:
                raise ValueError(f"Exercise {exercise_id} not found")

            # Find scenario
            scenario = next((s for s in exercise.scenarios if s.scenario_id == scenario_id), None)
            if not scenario:
                raise ValueError(f"Scenario {scenario_id} not found")

            # Create validation test
            test = ValidationTest(
                scenario=scenario,
                phase=exercise.current_phase,
                red_team_action=action,
                expected_blue_response=f"Detect and respond to {technique}",
                timestamp=datetime.now(timezone.utc)
            )

            self.active_tests[test.test_id] = test
            exercise.validation_tests.append(test)

            # Start monitoring for blue team response
            await self._start_blue_team_monitoring(test, exercise)

            # Log red team action
            await self._log_team_action("red_team", exercise_id, action, target, technique)

            return {
                "test_id": test.test_id,
                "status": "monitoring",
                "expected_detection_time": scenario.expected_detection_time,
                "validation_points": scenario.validation_points
            }

        except Exception as e:
            logging.error(f"Error executing red team action: {e}")
            raise

    async def validate_blue_team_response(self, test_id: str, detection_time: Optional[int] = None,
                                        response_actions: List[str] = None,
                                        evidence: List[Dict[str, Any]] = None) -> ValidationTest:
        """Validate blue team response to red team action"""
        try:
            test = self.active_tests.get(test_id)
            if not test:
                raise ValueError(f"Test {test_id} not found")

            # Update test results
            test.detection_time = detection_time
            test.response_time = detection_time  # Simplified
            test.actual_blue_response = "; ".join(response_actions or [])
            test.evidence = evidence or []

            # Determine validation result
            test.result = await self._determine_validation_result(test)
            test.confidence = await self._calculate_validation_confidence(test)

            # Generate lessons learned
            test.lessons_learned = await self._generate_lessons_learned(test)

            # Remove from active tests
            if test_id in self.active_tests:
                del self.active_tests[test_id]

            logging.info(f"Validated blue team response: {test.result.value}")

            return test

        except Exception as e:
            logging.error(f"Error validating blue team response: {e}")
            raise

    async def _load_scenario_library(self):
        """Load attack scenario library"""
        scenarios = [
            # Email Phishing Scenario
            AttackScenario(
                scenario_id="phishing_001",
                name="Credential Harvesting Phishing",
                description="Targeted phishing email to steal credentials",
                attack_vector=AttackVector.EMAIL_PHISHING,
                mitre_techniques=["T1566.002", "T1204.002", "T1555"],
                target_systems=["email_server", "user_workstations"],
                difficulty_level="medium",
                expected_detection_time=180,
                success_criteria=[
                    "Email blocked by security gateway",
                    "User reports suspicious email",
                    "SOC analyst investigates alert"
                ],
                validation_points=[
                    "Email security detection",
                    "User awareness effectiveness",
                    "SOC response time",
                    "Incident classification accuracy"
                ]
            ),

            # Malware Execution Scenario
            AttackScenario(
                scenario_id="malware_001",
                name="Fileless Malware Execution",
                description="Execute fileless malware using PowerShell",
                attack_vector=AttackVector.MALWARE_EXECUTION,
                mitre_techniques=["T1059.001", "T1055", "T1027"],
                target_systems=["windows_workstations"],
                difficulty_level="high",
                expected_detection_time=120,
                success_criteria=[
                    "EDR detects suspicious PowerShell activity",
                    "Process isolation initiated",
                    "Forensic analysis begins"
                ],
                validation_points=[
                    "EDR behavioral detection",
                    "PowerShell monitoring",
                    "Automated response effectiveness",
                    "Forensic evidence collection"
                ]
            ),

            # Lateral Movement Scenario
            AttackScenario(
                scenario_id="lateral_001",
                name="Internal Network Lateral Movement",
                description="Move laterally using stolen credentials",
                attack_vector=AttackVector.LATERAL_MOVEMENT,
                mitre_techniques=["T1021.001", "T1083", "T1018"],
                target_systems=["domain_controller", "file_servers"],
                difficulty_level="high",
                expected_detection_time=300,
                success_criteria=[
                    "Network monitoring detects anomalous RDP",
                    "Account activity correlation",
                    "Network segmentation enforcement"
                ],
                validation_points=[
                    "Network monitoring coverage",
                    "Identity correlation accuracy",
                    "Segmentation effectiveness",
                    "Privilege escalation detection"
                ]
            ),

            # Data Exfiltration Scenario
            AttackScenario(
                scenario_id="exfil_001",
                name="Sensitive Data Exfiltration",
                description="Exfiltrate sensitive data via DNS tunneling",
                attack_vector=AttackVector.DATA_EXFILTRATION,
                mitre_techniques=["T1041", "T1071.004", "T1020"],
                target_systems=["database_servers", "file_shares"],
                difficulty_level="advanced",
                expected_detection_time=600,
                success_criteria=[
                    "DLP solution detects data movement",
                    "DNS monitoring identifies tunneling",
                    "Data classification enforcement"
                ],
                validation_points=[
                    "DLP effectiveness",
                    "DNS monitoring capability",
                    "Data classification accuracy",
                    "Egress traffic analysis"
                ]
            ),

            # Persistence Scenario
            AttackScenario(
                scenario_id="persist_001",
                name="Registry-based Persistence",
                description="Establish persistence via registry modification",
                attack_vector=AttackVector.PERSISTENCE,
                mitre_techniques=["T1547.001", "T1112", "T1053.005"],
                target_systems=["windows_workstations", "servers"],
                difficulty_level="medium",
                expected_detection_time=240,
                success_criteria=[
                    "Registry monitoring detects changes",
                    "Startup persistence identified",
                    "Scheduled task analysis"
                ],
                validation_points=[
                    "Registry monitoring coverage",
                    "Persistence detection accuracy",
                    "Behavioral analysis effectiveness",
                    "Timeline reconstruction"
                ]
            )
        ]

        for scenario in scenarios:
            self.scenario_library[scenario.scenario_id] = scenario

    async def _initialize_validation_rules(self):
        """Initialize validation rules and criteria"""
        self.validation_rules = {
            "detection_timing": {
                "excellent": {"max_time": 60, "score": 1.0},
                "good": {"max_time": 300, "score": 0.8},
                "acceptable": {"max_time": 600, "score": 0.6},
                "poor": {"max_time": 1800, "score": 0.4},
                "failed": {"max_time": float('inf'), "score": 0.0}
            },
            "response_quality": {
                "automated_containment": 0.3,
                "accurate_classification": 0.2,
                "proper_escalation": 0.2,
                "evidence_collection": 0.15,
                "communication": 0.15
            },
            "false_positive_penalty": 0.1
        }

    async def _setup_collaboration_channels(self):
        """Setup real-time collaboration channels"""
        pass  # Implementation for team communication

    async def _is_exercise_event(self, event: BaseEvent) -> bool:
        """Check if event is related to active exercise"""
        try:
            # Check if any active exercise is monitoring for this type of event
            for exercise in self.active_exercises.values():
                if exercise.status == "active":
                    # Check against active validation tests
                    for test in self.active_tests.values():
                        if self._event_matches_test(event, test):
                            return True
            return False

        except Exception as e:
            logging.error(f"Error checking exercise event: {e}")
            return False

    def _event_matches_test(self, event: BaseEvent, test: ValidationTest) -> bool:
        """Check if event matches validation test criteria"""
        # Simple matching based on event type and timing
        event_types_mapping = {
            AttackVector.EMAIL_PHISHING: ["email_threat", "phishing_detected"],
            AttackVector.MALWARE_EXECUTION: ["malware_detection", "process_anomaly"],
            AttackVector.LATERAL_MOVEMENT: ["lateral_movement", "network_anomaly"],
            AttackVector.DATA_EXFILTRATION: ["data_exfiltration", "network_anomaly"],
            AttackVector.PERSISTENCE: ["persistence_detected", "registry_modification"]
        }

        expected_events = event_types_mapping.get(test.scenario.attack_vector, [])
        return event.event_type in expected_events

    async def _validate_blue_team_response(self, event: BaseEvent) -> Optional[Dict[str, Any]]:
        """Validate blue team response to detected event"""
        try:
            # Find matching active test
            matching_test = None
            for test in self.active_tests.values():
                if self._event_matches_test(event, test):
                    matching_test = test
                    break

            if not matching_test:
                return None

            # Calculate detection timing
            detection_time = (event.timestamp - matching_test.timestamp).total_seconds()

            # Auto-validate response
            validation_result = await self._auto_validate_response(event, matching_test, detection_time)

            return {
                "test_id": matching_test.test_id,
                "detection_time": detection_time,
                "validation_result": validation_result,
                "event_id": event.event_id
            }

        except Exception as e:
            logging.error(f"Error validating blue team response: {e}")
            return None

    async def _auto_validate_response(self, event: BaseEvent, test: ValidationTest, detection_time: float) -> Dict[str, Any]:
        """Automatically validate response quality"""
        try:
            # Determine result based on detection timing
            if detection_time <= test.scenario.expected_detection_time:
                result = ValidationResult.DETECTED
                score = 1.0
            elif detection_time <= test.scenario.expected_detection_time * 2:
                result = ValidationResult.DELAYED_DETECTION
                score = 0.7
            else:
                result = ValidationResult.MISSED
                score = 0.3

            # Check for response quality indicators
            response_quality = 0.0
            if event.enrichment.get("automated_response", False):
                response_quality += 0.3
            if event.enrichment.get("analyst_reviewed", False):
                response_quality += 0.2
            if event.enrichment.get("escalated", False):
                response_quality += 0.2

            final_score = (score + response_quality) / 2

            return {
                "result": result,
                "score": final_score,
                "detection_time": detection_time,
                "response_quality": response_quality,
                "confidence": 0.8
            }

        except Exception as e:
            logging.error(f"Error auto-validating response: {e}")
            return {"result": ValidationResult.MISSED, "score": 0.0, "confidence": 0.0}

    async def _determine_validation_result(self, test: ValidationTest) -> ValidationResult:
        """Determine final validation result"""
        if test.detection_time is None:
            return ValidationResult.MISSED

        expected_time = test.scenario.expected_detection_time

        if test.detection_time <= expected_time:
            return ValidationResult.DETECTED
        elif test.detection_time <= expected_time * 2:
            return ValidationResult.DELAYED_DETECTION
        else:
            return ValidationResult.MISSED

    async def _calculate_validation_confidence(self, test: ValidationTest) -> float:
        """Calculate confidence in validation result"""
        try:
            confidence = 0.5  # Base confidence

            # Increase confidence based on evidence quality
            if test.evidence:
                confidence += 0.2

            # Increase confidence based on response completeness
            if test.actual_blue_response:
                confidence += 0.2

            # Increase confidence based on timing consistency
            if test.detection_time and test.response_time:
                timing_consistency = abs(test.detection_time - test.response_time) / max(test.detection_time, 1)
                confidence += (1 - timing_consistency) * 0.1

            return min(confidence, 1.0)

        except Exception as e:
            logging.error(f"Error calculating validation confidence: {e}")
            return 0.5

    async def _generate_lessons_learned(self, test: ValidationTest) -> List[str]:
        """Generate lessons learned from validation test"""
        lessons = []

        try:
            if test.result == ValidationResult.MISSED:
                lessons.append("Detection capability gap identified - review monitoring rules")
                lessons.append("Consider additional detection signatures for this attack vector")

            elif test.result == ValidationResult.DELAYED_DETECTION:
                lessons.append("Detection timing can be improved - optimize alert prioritization")
                lessons.append("Review analyst workflows for faster response")

            elif test.result == ValidationResult.DETECTED:
                lessons.append("Excellent detection capability - maintain current controls")
                lessons.append("Consider this scenario for training other teams")

            # Scenario-specific lessons
            if test.scenario.attack_vector == AttackVector.EMAIL_PHISHING:
                lessons.append("Review email security gateway configuration")
                lessons.append("Enhance user awareness training programs")

            elif test.scenario.attack_vector == AttackVector.MALWARE_EXECUTION:
                lessons.append("Validate EDR behavioral detection rules")
                lessons.append("Review PowerShell execution policies")

        except Exception as e:
            logging.error(f"Error generating lessons learned: {e}")

        return lessons

    async def _start_blue_team_monitoring(self, test: ValidationTest, exercise: PurpleTeamExercise):
        """Start monitoring for blue team response"""
        try:
            # Set up monitoring timeout
            timeout_task = asyncio.create_task(
                self._test_timeout_handler(test, exercise.scenarios[0].expected_detection_time * 3)
            )

            # Log test start
            logging.info(f"Started monitoring for blue team response: {test.test_id}")

        except Exception as e:
            logging.error(f"Error starting blue team monitoring: {e}")

    async def _test_timeout_handler(self, test: ValidationTest, timeout_seconds: int):
        """Handle test timeout"""
        try:
            await asyncio.sleep(timeout_seconds)

            # Check if test is still active
            if test.test_id in self.active_tests:
                # Mark as missed
                test.result = ValidationResult.MISSED
                test.confidence = 1.0
                test.lessons_learned = ["Detection timeout - no response detected within expected timeframe"]

                # Remove from active tests
                del self.active_tests[test.test_id]

                logging.warning(f"Test {test.test_id} timed out - marked as missed")

        except Exception as e:
            logging.error(f"Error in test timeout handler: {e}")

    async def _log_team_action(self, team: str, exercise_id: str, action: str, target: str, technique: str):
        """Log team action for exercise tracking"""
        action_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "team": team,
            "exercise_id": exercise_id,
            "action": action,
            "target": target,
            "technique": technique
        }

        self.team_communications.append(action_log)

    async def _analyze_collaboration_opportunity(self, event: BaseEvent) -> Optional[Dict[str, Any]]:
        """Analyze potential collaboration opportunities"""
        try:
            # Check for events that would benefit from red-blue collaboration
            collaboration_events = [
                "false_positive",
                "missed_detection",
                "new_attack_technique",
                "control_failure"
            ]

            if event.event_type in collaboration_events:
                return {
                    "opportunity_type": "learning_session",
                    "description": f"Collaboration opportunity from {event.event_type}",
                    "suggested_actions": [
                        "Schedule joint red-blue analysis session",
                        "Review detection rules and signatures",
                        "Update attack scenarios based on findings"
                    ],
                    "priority": "medium"
                }

            return None

        except Exception as e:
            logging.error(f"Error analyzing collaboration opportunity: {e}")
            return None

    async def _notify_exercise_start(self, exercise: PurpleTeamExercise):
        """Notify teams of exercise start"""
        try:
            notification = {
                "type": "exercise_start",
                "exercise_id": exercise.exercise_id,
                "exercise_name": exercise.name,
                "scenarios": len(exercise.scenarios),
                "duration": (exercise.planned_end - exercise.planned_start).total_seconds() / 3600,
                "participants": exercise.participants
            }

            # In production, send to team communication channels
            logging.info(f"Exercise notification sent: {notification}")

        except Exception as e:
            logging.error(f"Error sending exercise notification: {e}")

    async def _initialize_exercise_tests(self, exercise: PurpleTeamExercise):
        """Initialize validation tests for exercise scenarios"""
        try:
            for scenario in exercise.scenarios:
                # Pre-create validation framework for each scenario
                validation_framework = {
                    "scenario_id": scenario.scenario_id,
                    "validation_points": scenario.validation_points,
                    "success_criteria": scenario.success_criteria,
                    "monitoring_rules": await self._create_monitoring_rules(scenario)
                }

                # Store framework for later use
                exercise.validation_tests.append(ValidationTest(scenario=scenario, phase=ExercisePhase.PREPARATION))

        except Exception as e:
            logging.error(f"Error initializing exercise tests: {e}")

    async def _create_monitoring_rules(self, scenario: AttackScenario) -> List[Dict[str, Any]]:
        """Create monitoring rules for scenario"""
        rules = []

        for technique in scenario.mitre_techniques:
            rule = {
                "technique": technique,
                "detection_methods": await self._get_detection_methods(technique),
                "expected_events": await self._get_expected_events(technique),
                "monitoring_duration": scenario.expected_detection_time * 2
            }
            rules.append(rule)

        return rules

    async def _get_detection_methods(self, technique: str) -> List[str]:
        """Get detection methods for MITRE technique"""
        # Simplified mapping
        detection_map = {
            "T1566.002": ["email_gateway", "user_reporting", "url_analysis"],
            "T1059.001": ["powershell_logging", "process_monitoring", "edr_detection"],
            "T1021.001": ["rdp_monitoring", "network_analysis", "authentication_logs"],
            "T1041": ["network_monitoring", "dlp_controls", "dns_analysis"]
        }

        return detection_map.get(technique, ["generic_monitoring"])

    async def _get_expected_events(self, technique: str) -> List[str]:
        """Get expected security events for MITRE technique"""
        # Simplified mapping
        event_map = {
            "T1566.002": ["email_threat", "phishing_detected", "user_report"],
            "T1059.001": ["process_anomaly", "malware_detection", "powershell_alert"],
            "T1021.001": ["lateral_movement", "rdp_anomaly", "authentication_anomaly"],
            "T1041": ["data_exfiltration", "network_anomaly", "dns_tunneling"]
        }

        return event_map.get(technique, ["security_alert"])

    async def _create_validation_event(self, trigger_event: BaseEvent, test_result: Dict[str, Any]) -> BaseEvent:
        """Create purple team validation event"""
        return BaseEvent(
            event_type="purple_team_validation",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.DETECTION_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="purple_team_validator",
            risk_score=30,
            enrichment={
                "validation_result": test_result,
                "trigger_event": trigger_event.event_id,
                "purple_team_exercise": True,
                "collaboration_insight": "Blue team response validated against red team action"
            }
        )

    async def _create_collaboration_event(self, trigger_event: BaseEvent, collaboration_insight: Dict[str, Any]) -> BaseEvent:
        """Create collaboration opportunity event"""
        return BaseEvent(
            event_type="purple_team_collaboration_opportunity",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.DETECTION_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="purple_team_validator",
            risk_score=20,
            enrichment={
                "collaboration_insight": collaboration_insight,
                "trigger_event": trigger_event.event_id,
                "opportunity_type": collaboration_insight["opportunity_type"],
                "suggested_actions": collaboration_insight["suggested_actions"]
            }
        )

    async def cleanup(self) -> None:
        """Cleanup purple team validator"""
        try:
            # Complete any active exercises
            for exercise in self.active_exercises.values():
                if exercise.status == "active":
                    exercise.status = "cancelled"
                    exercise.actual_end = datetime.now(timezone.utc)

            self.active_exercises.clear()
            self.active_tests.clear()

            logging.info("Purple Team Validator cleanup completed")

        except Exception as e:
            logging.error(f"Error during purple team validator cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get purple team validator metrics"""
        return {
            **super().get_metrics(),
            "active_exercises": len(self.active_exercises),
            "total_exercises_completed": len(self.exercise_history),
            "scenario_library_size": len(self.scenario_library),
            "active_validation_tests": len(self.active_tests),
            "team_metrics_tracked": len(self.team_metrics),
            "collaboration_opportunities": len([c for c in self.team_communications
                                             if c.get("type") == "collaboration_opportunity"]),
            "average_detection_rate": self._calculate_average_detection_rate(),
            "average_response_time": self._calculate_average_response_time()
        }

    def _calculate_average_detection_rate(self) -> float:
        """Calculate average detection rate across exercises"""
        if not self.exercise_history:
            return 0.0

        total_rate = sum(ex.detection_rate for ex in self.exercise_history)
        return total_rate / len(self.exercise_history)

    def _calculate_average_response_time(self) -> float:
        """Calculate average response time across exercises"""
        all_tests = []
        for exercise in self.exercise_history:
            all_tests.extend(exercise.validation_tests)

        if not all_tests:
            return 0.0

        response_times = [test.response_time for test in all_tests if test.response_time]
        return sum(response_times) / len(response_times) if response_times else 0.0


# Global instance
purple_team_validator = PurpleTeamValidator()