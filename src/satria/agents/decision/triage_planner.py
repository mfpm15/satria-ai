"""
SATRIA AI - Triage Planner Agent
Automated incident triage and response planning using QDE
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.quantum_decision_engine import qde, DecisionContext
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.context_graph import context_graph


class TriagePriority(str, Enum):
    """Triage priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageStatus(str, Enum):
    """Triage status"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class TriageCase:
    """Incident triage case"""
    case_id: str
    title: str
    description: str
    priority: TriagePriority
    status: TriageStatus
    events: List[BaseEvent]
    entity_ids: Dict[str, str]
    risk_score: int
    confidence: float
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    response_plan: Optional[Dict[str, Any]] = None
    sla_deadline: Optional[datetime] = None
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class TriagePlannerAgent(BaseAgent):
    """
    Priority Agent 4: Triage Planner
    Automated incident triage, correlation, and response planning
    """

    def __init__(self):
        super().__init__(
            name="triage_planner",
            description="Automated incident triage and response planning",
            version="1.0.0"
        )
        self.active_cases: Dict[str, TriageCase] = {}
        self.processed_events = 0
        self.cases_created = 0
        self.auto_resolved = 0

        # Triage thresholds
        self.risk_thresholds = {
            TriagePriority.CRITICAL: 85,
            TriagePriority.HIGH: 65,
            TriagePriority.MEDIUM: 40,
            TriagePriority.LOW: 20
        }

        # SLA deadlines (in hours)
        self.sla_deadlines = {
            TriagePriority.CRITICAL: 1,
            TriagePriority.HIGH: 4,
            TriagePriority.MEDIUM: 24,
            TriagePriority.LOW: 72
        }

    async def initialize(self) -> bool:
        """Initialize triage planner"""
        try:
            logging.info("Triage Planner Agent initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Triage Planner: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> Optional[BaseEvent]:
        """Process events for triage and case management"""
        try:
            self.processed_events += 1

            # Skip low-risk events
            if event.risk < self.risk_thresholds[TriagePriority.LOW]:
                return event

            # Check if event belongs to existing case
            existing_case = await self._find_related_case(event)

            if existing_case:
                # Update existing case
                await self._update_case(existing_case, event)
            else:
                # Create new case if risk is significant
                if event.risk >= self.risk_thresholds[TriagePriority.MEDIUM]:
                    await self._create_new_case(event)

            return event

        except Exception as e:
            logging.error(f"Error processing event in triage planner: {e}")
            return event

    async def _find_related_case(self, event: BaseEvent) -> Optional[TriageCase]:
        """Find existing case that this event belongs to"""
        # Check by entity correlation
        for case in self.active_cases.values():
            if case.status in [TriageStatus.RESOLVED, TriageStatus.FALSE_POSITIVE]:
                continue

            # Check for entity overlap
            event_entities = set(event.entity_ids.values())
            case_entities = set(case.entity_ids.values())

            if event_entities & case_entities:
                # Check temporal proximity (events within 1 hour)
                time_diff = abs((event.timestamp - case.created_at).total_seconds())
                if time_diff <= 3600:  # 1 hour
                    return case

            # Check for same attack pattern
            if self._is_same_attack_pattern(event, case):
                return case

        return None

    async def _create_new_case(self, event: BaseEvent) -> TriageCase:
        """Create new triage case"""
        try:
            # Generate case ID
            case_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(self.active_cases) + 1:04d}"

            # Determine priority based on risk score
            priority = self._calculate_priority(event.risk)

            # Generate title and description
            title = self._generate_case_title(event)
            description = self._generate_case_description(event)

            # Calculate SLA deadline
            sla_hours = self.sla_deadlines[priority]
            sla_deadline = datetime.now(timezone.utc) + timedelta(hours=sla_hours)

            # Create case
            case = TriageCase(
                case_id=case_id,
                title=title,
                description=description,
                priority=priority,
                status=TriageStatus.OPEN,
                events=[event],
                entity_ids=event.entity_ids.copy(),
                risk_score=event.risk,
                confidence=event.confidence,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                sla_deadline=sla_deadline,
                tags=self._generate_case_tags(event)
            )

            # Generate response plan using QDE
            case.response_plan = await self._generate_response_plan(case)

            # Auto-assign for critical cases
            if priority == TriagePriority.CRITICAL:
                case.assigned_to = "security-team-lead"
                case.status = TriageStatus.IN_PROGRESS

            # Store case
            self.active_cases[case_id] = case
            self.cases_created += 1

            # Log case creation
            logging.info(f"Created triage case {case_id}: {title} (Priority: {priority.value})")

            # Notify via event bus
            await self._notify_case_created(case)

            return case

        except Exception as e:
            logging.error(f"Error creating triage case: {e}")
            raise

    async def _update_case(self, case: TriageCase, event: BaseEvent):
        """Update existing case with new event"""
        try:
            # Add event to case
            case.events.append(event)

            # Update risk score (take maximum or calculate weighted average)
            if event.risk > case.risk_score:
                case.risk_score = event.risk
                # Recalculate priority if needed
                new_priority = self._calculate_priority(event.risk)
                if new_priority.value != case.priority.value:
                    logging.info(f"Escalating case {case.case_id} from {case.priority.value} to {new_priority.value}")
                    case.priority = new_priority

            # Update entity IDs
            case.entity_ids.update(event.entity_ids)

            # Update timestamp
            case.updated_at = datetime.now(timezone.utc)

            # Add new tags
            event_tags = self._generate_case_tags(event)
            case.tags.extend([tag for tag in event_tags if tag not in case.tags])

            # Update response plan if significant changes
            if event.risk >= 70:
                case.response_plan = await self._generate_response_plan(case)

            logging.info(f"Updated case {case.case_id} with new event (Risk: {event.risk})")

        except Exception as e:
            logging.error(f"Error updating case {case.case_id}: {e}")

    def _calculate_priority(self, risk_score: int) -> TriagePriority:
        """Calculate triage priority based on risk score"""
        for priority, threshold in self.risk_thresholds.items():
            if risk_score >= threshold:
                return priority
        return TriagePriority.INFO

    def _generate_case_title(self, event: BaseEvent) -> str:
        """Generate descriptive case title"""
        entity_desc = ""
        if "host" in event.entity_ids:
            entity_desc = f" on {event.entity_ids['host']}"
        elif "user" in event.entity_ids:
            entity_desc = f" for user {event.entity_ids['user']}"

        type_descriptions = {
            "edr_detection": "EDR Security Alert",
            "authentication_failure": "Authentication Anomaly",
            "network_connection": "Suspicious Network Activity",
            "file_modification": "File System Anomaly",
            "process_anomaly": "Process Execution Anomaly",
            "webshell_detection": "Webshell Detection"
        }

        title_base = type_descriptions.get(event.event_type, f"Security Event ({event.event_type})")
        return f"{title_base}{entity_desc}"

    def _generate_case_description(self, event: BaseEvent) -> str:
        """Generate detailed case description"""
        description = f"Security incident detected at {event.timestamp.isoformat()}\n\n"
        description += f"Event Type: {event.event_type}\n"
        description += f"Risk Score: {event.risk}/100\n"
        description += f"Confidence: {event.confidence:.2f}\n\n"

        if event.entity_ids:
            description += "Affected Entities:\n"
            for key, value in event.entity_ids.items():
                description += f"  - {key.title()}: {value}\n"

        if event.message:
            description += f"\nDescription: {event.message}\n"

        # Add key enrichment data
        if event.enrichment:
            key_fields = ["platform", "detection_type", "process", "command_line", "source_ip", "dest_ip"]
            enrichment_details = []
            for field in key_fields:
                if field in event.enrichment:
                    enrichment_details.append(f"  - {field.title()}: {event.enrichment[field]}")

            if enrichment_details:
                description += "\nKey Details:\n" + "\n".join(enrichment_details)

        return description

    def _generate_case_tags(self, event: BaseEvent) -> List[str]:
        """Generate tags for the case"""
        tags = []

        # Event type tags
        tags.append(f"event_type:{event.event_type}")
        tags.append(f"category:{event.event_category.value}")

        # Risk level tags
        if event.risk >= 85:
            tags.append("critical")
        elif event.risk >= 65:
            tags.append("high_risk")

        # Platform tags
        if "platform" in event.enrichment:
            tags.append(f"platform:{event.enrichment['platform']}")

        # Entity tags
        for entity_type, entity_value in event.entity_ids.items():
            tags.append(f"{entity_type}:{entity_value}")

        return tags

    async def _generate_response_plan(self, case: TriageCase) -> Dict[str, Any]:
        """Generate automated response plan using QDE"""
        try:
            # Create decision context
            context = DecisionContext(
                threat_level=case.priority.value,
                asset_criticality="high" if case.risk_score >= 70 else "medium",
                event_context={
                    "event_types": [event.event_type for event in case.events],
                    "entities": case.entity_ids,
                    "risk_score": case.risk_score,
                    "confidence": case.confidence
                },
                constraints={
                    "max_automation_level": "containment" if case.priority == TriagePriority.CRITICAL else "investigate",
                    "approval_required": case.priority in [TriagePriority.CRITICAL, TriagePriority.HIGH]
                }
            )

            # Get QDE decision
            decision = await qde.decide(context)

            # Convert to response plan
            response_plan = {
                "plan_id": decision.action_plan.plan_id,
                "stage": decision.action_plan.stage.value,
                "priority": decision.action_plan.priority.value,
                "actions": decision.action_plan.actions,
                "approval_required": decision.action_plan.approval_required,
                "estimated_duration": decision.action_plan.estimated_duration.total_seconds(),
                "persona_recommendation": {
                    "dominant_persona": decision.persona_mix.dominant_persona.value,
                    "elliot_weight": decision.persona_mix.elliot_weight,
                    "mr_robot_weight": decision.persona_mix.mr_robot_weight,
                    "reasoning": decision.persona_mix.reasoning
                },
                "generated_at": datetime.now(timezone.utc).isoformat()
            }

            return response_plan

        except Exception as e:
            logging.error(f"Error generating response plan: {e}")
            return {
                "plan_id": f"manual-{case.case_id}",
                "stage": "investigate",
                "actions": ["Manual analysis required"],
                "approval_required": True,
                "error": str(e)
            }

    def _is_same_attack_pattern(self, event: BaseEvent, case: TriageCase) -> bool:
        """Check if event matches existing attack pattern in case"""
        # Simple pattern matching - can be enhanced
        if not case.events:
            return False

        # Check for similar event types
        case_event_types = set(e.event_type for e in case.events)
        if event.event_type in case_event_types:
            return True

        # Check for attack chain patterns
        attack_chains = [
            ["authentication_failure", "authentication_success", "lateral_movement"],
            ["network_connection", "process_anomaly", "file_modification"],
            ["edr_detection", "network_connection", "data_exfiltration"]
        ]

        for chain in attack_chains:
            if event.event_type in chain:
                case_types_in_chain = [t for t in case_event_types if t in chain]
                if case_types_in_chain:
                    return True

        return False

    async def _notify_case_created(self, case: TriageCase):
        """Notify about new case creation"""
        notification_event = BaseEvent(
            event_type="triage_case_created",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.DETECTION_FINDING,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"case_id": case.case_id},
            message=f"New triage case created: {case.title}",
            risk=case.risk_score,
            confidence=case.confidence,
            enrichment={
                "case_details": {
                    "case_id": case.case_id,
                    "priority": case.priority.value,
                    "status": case.status.value,
                    "sla_deadline": case.sla_deadline.isoformat() if case.sla_deadline else None,
                    "assigned_to": case.assigned_to,
                    "event_count": len(case.events)
                }
            }
        )

        await event_bus.publish(notification_event)

    async def get_case(self, case_id: str) -> Optional[TriageCase]:
        """Get specific triage case"""
        return self.active_cases.get(case_id)

    async def get_active_cases(self, priority: Optional[TriagePriority] = None) -> List[TriageCase]:
        """Get active triage cases"""
        cases = [case for case in self.active_cases.values()
                if case.status not in [TriageStatus.RESOLVED, TriageStatus.FALSE_POSITIVE]]

        if priority:
            cases = [case for case in cases if case.priority == priority]

        return sorted(cases, key=lambda x: x.created_at, reverse=True)

    async def resolve_case(self, case_id: str, resolution: str, resolved_by: str):
        """Resolve a triage case"""
        if case_id in self.active_cases:
            case = self.active_cases[case_id]
            case.status = TriageStatus.RESOLVED
            case.updated_at = datetime.now(timezone.utc)

            # Add resolution details
            if "resolution" not in case.__dict__:
                case.__dict__["resolution"] = {
                    "resolution": resolution,
                    "resolved_by": resolved_by,
                    "resolved_at": datetime.now(timezone.utc).isoformat()
                }

            self.auto_resolved += 1
            logging.info(f"Resolved case {case_id}: {resolution}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Save active cases to persistent storage
            if self.active_cases:
                self.logger.debug(f"Saving {len(self.active_cases)} active triage cases")

            # Clear in-memory data
            self.active_cases.clear()
            self.case_history.clear()

            self.logger.info("Triage planner cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get triage planner metrics"""
        active_cases_by_priority = {}
        for priority in TriagePriority:
            count = len([case for case in self.active_cases.values()
                        if case.priority == priority and
                        case.status not in [TriageStatus.RESOLVED, TriageStatus.FALSE_POSITIVE]])
            active_cases_by_priority[priority.value] = count

        return {
            **super().get_metrics(),
            "processed_events": self.processed_events,
            "total_cases": len(self.active_cases),
            "cases_created": self.cases_created,
            "auto_resolved": self.auto_resolved,
            "active_cases_by_priority": active_cases_by_priority,
            "risk_thresholds": {k.value: v for k, v in self.risk_thresholds.items()}
        }


# Global instance
triage_planner = TriagePlannerAgent()