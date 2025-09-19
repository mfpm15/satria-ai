"""
SATRIA AI - Autonomous Response Orchestrator
Phase 3: Core autonomous response coordination and execution
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class ResponseAction(str, Enum):
    """Types of autonomous response actions"""
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    PATCH_VULNERABILITY = "patch_vulnerability"
    SCALE_RESOURCES = "scale_resources"
    BACKUP_DATA = "backup_data"
    ALERT_TEAM = "alert_team"
    CREATE_CASE = "create_case"
    ROLLBACK_CHANGES = "rollback_changes"
    ACTIVATE_DRP = "activate_drp"


class ResponseUrgency(str, Enum):
    """Response urgency levels"""
    IMMEDIATE = "immediate"        # <1 minute
    URGENT = "urgent"             # <5 minutes
    HIGH = "high"                 # <15 minutes
    MEDIUM = "medium"             # <30 minutes
    LOW = "low"                   # <2 hours


class ResponseStatus(str, Enum):
    """Response execution status"""
    PENDING = "pending"
    PLANNING = "planning"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResponsePlan:
    """Autonomous response plan"""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    trigger_event: Optional[BaseEvent] = None
    urgency: ResponseUrgency = ResponseUrgency.MEDIUM
    confidence: float = 0.0
    actions: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    rollback_plan: List[Dict[str, Any]] = field(default_factory=list)
    estimated_impact: Dict[str, Any] = field(default_factory=dict)
    approval_required: bool = True
    auto_execute: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: ResponseStatus = ResponseStatus.PENDING


@dataclass
class ResponseMetrics:
    """Response execution metrics"""
    total_responses: int = 0
    successful_responses: int = 0
    failed_responses: int = 0
    auto_executed: int = 0
    manual_approved: int = 0
    avg_response_time: float = 0.0
    avg_plan_generation_time: float = 0.0


class AutonomousResponseOrchestrator(BaseAgent):
    """
    Phase 3: Autonomous Response Orchestrator
    Coordinates intelligent, automated responses to security incidents
    """

    def __init__(self):
        super().__init__(
            name="autonomous_response_orchestrator",
            description="Autonomous response coordination and execution",
            version="3.0.0"
        )

        self.active_responses: Dict[str, ResponsePlan] = {}
        self.response_history: List[ResponsePlan] = []
        self.metrics = ResponseMetrics()
        self.automation_rules: Dict[str, Dict[str, Any]] = {}
        self.safety_constraints: Dict[str, Any] = {}

        # Response decision thresholds
        self.decision_thresholds = {
            "auto_execute_confidence": 0.95,
            "auto_execute_max_risk": 30,
            "isolation_threshold": 85,
            "blocking_threshold": 75,
            "user_disable_threshold": 80
        }

    async def initialize(self) -> bool:
        """Initialize autonomous response orchestrator"""
        try:
            # Load automation rules and safety constraints
            await self._load_automation_rules()
            await self._load_safety_constraints()

            # Initialize response capabilities
            await self._initialize_response_capabilities()

            logging.info("Autonomous Response Orchestrator initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Autonomous Response Orchestrator: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process security events for autonomous response"""
        try:
            # Check if event requires autonomous response
            if not await self._should_trigger_response(event):
                return [event]

            # Generate response plan
            response_plan = await self._generate_response_plan(event)

            if response_plan:
                # Store active response
                self.active_responses[response_plan.plan_id] = response_plan

                # Decide on execution strategy
                if await self._should_auto_execute(response_plan):
                    # Execute immediately for high-confidence, low-risk responses
                    await self._execute_response_plan(response_plan)
                else:
                    # Queue for approval or manual review
                    await self._queue_for_approval(response_plan)

                # Create response event
                response_event = await self._create_response_event(event, response_plan)
                return [event, response_event]

            return [event]

        except Exception as e:
            logging.error(f"Error processing event for autonomous response: {e}")
            return [event]

    async def _should_trigger_response(self, event: BaseEvent) -> bool:
        """Determine if event should trigger autonomous response"""
        try:
            # Check event risk score
            if event.risk < 50:
                return False

            # Check if event type is actionable
            actionable_types = [
                "malware_detection",
                "authentication_failure",
                "lateral_movement",
                "data_exfiltration",
                "privilege_escalation",
                "network_anomaly",
                "file_modification"
            ]

            if event.event_type not in actionable_types:
                return False

            # Check if recent response already exists
            if await self._has_recent_response(event):
                return False

            return True

        except Exception as e:
            logging.error(f"Error checking response trigger: {e}")
            return False

    async def _generate_response_plan(self, event: BaseEvent) -> Optional[ResponsePlan]:
        """Generate autonomous response plan using AI"""
        try:
            start_time = datetime.now(timezone.utc)

            # Gather context for response planning
            context = await self._gather_response_context(event)

            # Use LLM to generate response strategy
            response_strategy = await self._llm_generate_response_strategy(event, context)

            # Convert strategy to executable plan
            response_plan = await self._create_executable_plan(event, response_strategy, context)

            # Calculate generation time
            generation_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.metrics.avg_plan_generation_time = (
                (self.metrics.avg_plan_generation_time * self.metrics.total_responses + generation_time)
                / (self.metrics.total_responses + 1)
            )

            return response_plan

        except Exception as e:
            logging.error(f"Error generating response plan: {e}")
            return None

    async def _llm_generate_response_strategy(self, event: BaseEvent, context: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to generate intelligent response strategy"""
        try:
            system_prompt = """You are SATRIA AI's Autonomous Response Strategist.
Generate intelligent, precise response strategies for cybersecurity incidents.

Your response must be a JSON object with this structure:
{
    "urgency": "immediate|urgent|high|medium|low",
    "confidence": 0.0-1.0,
    "primary_actions": [
        {
            "action": "action_type",
            "target": "target_identifier",
            "priority": 1-10,
            "risk_level": "low|medium|high|critical",
            "estimated_time": "time_estimate",
            "rollback_possible": true/false
        }
    ],
    "secondary_actions": [...],
    "constraints": ["constraint1", "constraint2"],
    "success_criteria": ["criteria1", "criteria2"],
    "rollback_strategy": ["step1", "step2"]
}

Consider business impact, false positive risk, and operational constraints."""

            user_prompt = f"""Incident Analysis:
Event Type: {event.event_type}
Risk Score: {event.risk}/100
Confidence: {event.confidence}
Affected Entities: {event.entity_ids}
Message: {event.message}

Context:
- Similar Past Incidents: {len(context.get('similar_incidents', []))}
- Current System Load: {context.get('system_load', 'normal')}
- Business Hours: {context.get('business_hours', True)}
- Critical Systems Affected: {context.get('critical_systems', [])}

Generate an autonomous response strategy with specific, executable actions."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt)
            ]

            response = await llm_client.chat_completion(
                messages=messages,
                temperature=0.3,
                max_tokens=1500
            )

            # Parse LLM response as JSON
            try:
                strategy = json.loads(response.content)
                return strategy
            except json.JSONDecodeError:
                # Fallback to rule-based response if LLM response isn't valid JSON
                return await self._fallback_response_strategy(event, context)

        except Exception as e:
            logging.error(f"Error generating LLM response strategy: {e}")
            return await self._fallback_response_strategy(event, context)

    async def _fallback_response_strategy(self, event: BaseEvent, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based response strategy"""
        strategy = {
            "urgency": "medium",
            "confidence": 0.7,
            "primary_actions": [],
            "secondary_actions": [],
            "constraints": ["require_approval"],
            "success_criteria": ["threat_contained"],
            "rollback_strategy": ["restore_from_backup"]
        }

        # Rule-based action selection
        if event.risk >= 85:
            strategy["urgency"] = "immediate"
            if event.event_type == "malware_detection":
                strategy["primary_actions"].append({
                    "action": "isolate_host",
                    "target": event.entity_ids.get("host", "unknown"),
                    "priority": 1,
                    "risk_level": "medium",
                    "estimated_time": "2 minutes",
                    "rollback_possible": True
                })

        elif event.risk >= 70:
            strategy["urgency"] = "high"
            if "authentication_failure" in event.event_type:
                strategy["primary_actions"].append({
                    "action": "disable_user",
                    "target": event.entity_ids.get("user", "unknown"),
                    "priority": 2,
                    "risk_level": "low",
                    "estimated_time": "1 minute",
                    "rollback_possible": True
                })

        return strategy

    async def _create_executable_plan(self, event: BaseEvent, strategy: Dict[str, Any], context: Dict[str, Any]) -> ResponsePlan:
        """Convert strategy to executable response plan"""
        try:
            plan = ResponsePlan(
                incident_id=f"INC-{datetime.now().strftime('%Y%m%d')}-{event.event_id[:8]}",
                trigger_event=event,
                urgency=ResponseUrgency(strategy.get("urgency", "medium")),
                confidence=float(strategy.get("confidence", 0.7))
            )

            # Convert actions to executable format
            all_actions = strategy.get("primary_actions", []) + strategy.get("secondary_actions", [])

            for action_spec in all_actions:
                executable_action = await self._create_executable_action(action_spec, event, context)
                if executable_action:
                    plan.actions.append(executable_action)

            # Set execution policy
            plan.auto_execute = (
                plan.confidence >= self.decision_thresholds["auto_execute_confidence"] and
                event.risk <= self.decision_thresholds["auto_execute_max_risk"] and
                await self._passes_safety_checks(plan)
            )

            # Generate rollback plan
            plan.rollback_plan = await self._generate_rollback_plan(plan.actions)

            return plan

        except Exception as e:
            logging.error(f"Error creating executable plan: {e}")
            return None

    async def _create_executable_action(self, action_spec: Dict[str, Any], event: BaseEvent, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create executable action from specification"""
        try:
            action_type = action_spec.get("action", "").upper()

            # Map to ResponseAction enum
            action_mapping = {
                "ISOLATE_HOST": ResponseAction.ISOLATE_HOST,
                "BLOCK_IP": ResponseAction.BLOCK_IP,
                "DISABLE_USER": ResponseAction.DISABLE_USER,
                "QUARANTINE_FILE": ResponseAction.QUARANTINE_FILE,
                "RESET_PASSWORD": ResponseAction.RESET_PASSWORD
            }

            if action_type not in action_mapping:
                return None

            executable_action = {
                "id": str(uuid.uuid4()),
                "action": action_mapping[action_type].value,
                "target": action_spec.get("target", ""),
                "priority": action_spec.get("priority", 5),
                "parameters": await self._get_action_parameters(action_mapping[action_type], action_spec, event),
                "estimated_duration": action_spec.get("estimated_time", "5 minutes"),
                "risk_level": action_spec.get("risk_level", "medium"),
                "rollback_possible": action_spec.get("rollback_possible", True),
                "status": "pending",
                "created_at": datetime.now(timezone.utc).isoformat()
            }

            return executable_action

        except Exception as e:
            logging.error(f"Error creating executable action: {e}")
            return None

    async def _get_action_parameters(self, action: ResponseAction, spec: Dict[str, Any], event: BaseEvent) -> Dict[str, Any]:
        """Get specific parameters for each action type"""
        parameters = {}

        if action == ResponseAction.ISOLATE_HOST:
            parameters = {
                "host_id": spec.get("target"),
                "isolation_type": "network",
                "duration": "24h",
                "allow_management": True,
                "notify_user": True
            }

        elif action == ResponseAction.BLOCK_IP:
            parameters = {
                "ip_address": spec.get("target"),
                "block_type": "firewall",
                "duration": "1h",
                "scope": "all_interfaces"
            }

        elif action == ResponseAction.DISABLE_USER:
            parameters = {
                "username": spec.get("target"),
                "disable_type": "account_lock",
                "duration": "2h",
                "notify_manager": True
            }

        elif action == ResponseAction.QUARANTINE_FILE:
            parameters = {
                "file_path": spec.get("target"),
                "quarantine_location": "/quarantine/",
                "preserve_metadata": True,
                "create_backup": True
            }

        return parameters

    async def _should_auto_execute(self, plan: ResponsePlan) -> bool:
        """Determine if response plan should be auto-executed"""
        try:
            # Check confidence threshold
            if plan.confidence < self.decision_thresholds["auto_execute_confidence"]:
                return False

            # Check risk threshold
            if plan.trigger_event and plan.trigger_event.risk > self.decision_thresholds["auto_execute_max_risk"]:
                return False

            # Check safety constraints
            if not await self._passes_safety_checks(plan):
                return False

            # Check business hours for low-risk actions
            if plan.urgency in [ResponseUrgency.LOW, ResponseUrgency.MEDIUM]:
                if not await self._is_business_hours():
                    return False

            return plan.auto_execute

        except Exception as e:
            logging.error(f"Error checking auto-execution criteria: {e}")
            return False

    async def _execute_response_plan(self, plan: ResponsePlan) -> bool:
        """Execute autonomous response plan"""
        try:
            start_time = datetime.now(timezone.utc)
            plan.status = ResponseStatus.EXECUTING

            logging.info(f"Executing autonomous response plan {plan.plan_id}")

            # Execute actions in priority order
            sorted_actions = sorted(plan.actions, key=lambda a: a.get("priority", 5))

            success_count = 0
            for action in sorted_actions:
                try:
                    success = await self._execute_action(action, plan)
                    if success:
                        success_count += 1
                        action["status"] = "completed"
                        action["completed_at"] = datetime.now(timezone.utc).isoformat()
                    else:
                        action["status"] = "failed"
                        action["failed_at"] = datetime.now(timezone.utc).isoformat()

                        # Consider rollback on critical action failure
                        if action.get("priority", 5) <= 2:
                            await self._consider_rollback(plan, action)

                except Exception as e:
                    logging.error(f"Error executing action {action['id']}: {e}")
                    action["status"] = "error"
                    action["error"] = str(e)

            # Update plan status
            if success_count == len(plan.actions):
                plan.status = ResponseStatus.COMPLETED
                self.metrics.successful_responses += 1
            else:
                plan.status = ResponseStatus.FAILED
                self.metrics.failed_responses += 1

            # Update metrics
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.metrics.total_responses += 1
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * (self.metrics.total_responses - 1) + execution_time)
                / self.metrics.total_responses
            )

            if plan.auto_execute:
                self.metrics.auto_executed += 1

            # Move to history
            self.response_history.append(plan)
            if plan.plan_id in self.active_responses:
                del self.active_responses[plan.plan_id]

            logging.info(f"Response plan {plan.plan_id} completed with status: {plan.status}")
            return plan.status == ResponseStatus.COMPLETED

        except Exception as e:
            logging.error(f"Error executing response plan: {e}")
            plan.status = ResponseStatus.FAILED
            return False

    async def _execute_action(self, action: Dict[str, Any], plan: ResponsePlan) -> bool:
        """Execute individual response action"""
        try:
            action_type = ResponseAction(action["action"])
            parameters = action.get("parameters", {})

            logging.info(f"Executing action: {action_type.value} on {action.get('target')}")

            if action_type == ResponseAction.ISOLATE_HOST:
                return await self._isolate_host(parameters)
            elif action_type == ResponseAction.BLOCK_IP:
                return await self._block_ip(parameters)
            elif action_type == ResponseAction.DISABLE_USER:
                return await self._disable_user(parameters)
            elif action_type == ResponseAction.QUARANTINE_FILE:
                return await self._quarantine_file(parameters)
            elif action_type == ResponseAction.RESET_PASSWORD:
                return await self._reset_password(parameters)
            else:
                logging.warning(f"Unknown action type: {action_type}")
                return False

        except Exception as e:
            logging.error(f"Error executing action: {e}")
            return False

    async def _isolate_host(self, parameters: Dict[str, Any]) -> bool:
        """Isolate host from network"""
        try:
            host_id = parameters.get("host_id")
            isolation_type = parameters.get("isolation_type", "network")

            # Simulate host isolation (in production, integrate with EDR/network tools)
            logging.info(f"Isolating host {host_id} with {isolation_type} isolation")

            # Create isolation command
            isolation_command = {
                "action": "isolate",
                "target": host_id,
                "type": isolation_type,
                "duration": parameters.get("duration", "24h"),
                "allow_management": parameters.get("allow_management", True)
            }

            # In production: send to EDR connector or network controller
            # For now, simulate success
            await asyncio.sleep(0.1)  # Simulate network call

            logging.info(f"Host {host_id} isolated successfully")
            return True

        except Exception as e:
            logging.error(f"Error isolating host: {e}")
            return False

    async def _block_ip(self, parameters: Dict[str, Any]) -> bool:
        """Block IP address"""
        try:
            ip_address = parameters.get("ip_address")
            block_type = parameters.get("block_type", "firewall")

            logging.info(f"Blocking IP {ip_address} via {block_type}")

            # Simulate firewall rule creation
            await asyncio.sleep(0.1)

            logging.info(f"IP {ip_address} blocked successfully")
            return True

        except Exception as e:
            logging.error(f"Error blocking IP: {e}")
            return False

    async def _disable_user(self, parameters: Dict[str, Any]) -> bool:
        """Disable user account"""
        try:
            username = parameters.get("username")
            disable_type = parameters.get("disable_type", "account_lock")

            logging.info(f"Disabling user {username} with {disable_type}")

            # Simulate user account disable
            await asyncio.sleep(0.1)

            logging.info(f"User {username} disabled successfully")
            return True

        except Exception as e:
            logging.error(f"Error disabling user: {e}")
            return False

    async def _quarantine_file(self, parameters: Dict[str, Any]) -> bool:
        """Quarantine malicious file"""
        try:
            file_path = parameters.get("file_path")
            quarantine_location = parameters.get("quarantine_location", "/quarantine/")

            logging.info(f"Quarantining file {file_path}")

            # Simulate file quarantine
            await asyncio.sleep(0.1)

            logging.info(f"File {file_path} quarantined successfully")
            return True

        except Exception as e:
            logging.error(f"Error quarantining file: {e}")
            return False

    async def _reset_password(self, parameters: Dict[str, Any]) -> bool:
        """Reset user password"""
        try:
            username = parameters.get("username")

            logging.info(f"Resetting password for user {username}")

            # Simulate password reset
            await asyncio.sleep(0.1)

            logging.info(f"Password reset for user {username} completed")
            return True

        except Exception as e:
            logging.error(f"Error resetting password: {e}")
            return False

    async def _gather_response_context(self, event: BaseEvent) -> Dict[str, Any]:
        """Gather context for response planning"""
        try:
            context = {
                "similar_incidents": [],
                "system_load": "normal",
                "business_hours": await self._is_business_hours(),
                "critical_systems": [],
                "recent_changes": [],
                "available_resources": []
            }

            # Get similar incidents from memory
            try:
                # This would integrate with incident memory system
                context["similar_incidents"] = []
            except Exception:
                pass

            # Check system load
            context["system_load"] = await self._check_system_load()

            # Identify critical systems
            if event.entity_ids:
                context["critical_systems"] = await self._identify_critical_systems(event.entity_ids)

            return context

        except Exception as e:
            logging.error(f"Error gathering response context: {e}")
            return {}

    async def _load_automation_rules(self):
        """Load automation rules and policies"""
        self.automation_rules = {
            "malware_detection": {
                "auto_quarantine": True,
                "auto_isolate_threshold": 85,
                "require_approval": False
            },
            "authentication_failure": {
                "auto_disable_threshold": 80,
                "lockout_duration": "2h",
                "require_approval": True
            },
            "lateral_movement": {
                "auto_isolate": True,
                "network_segmentation": True,
                "require_approval": False
            }
        }

    async def _load_safety_constraints(self):
        """Load safety constraints and limits"""
        self.safety_constraints = {
            "max_simultaneous_isolations": 5,
            "max_users_disabled_per_hour": 10,
            "critical_systems_require_approval": True,
            "business_hours_only": ["user_management", "system_changes"],
            "rollback_required_actions": ["isolate_host", "disable_user"]
        }

    async def _initialize_response_capabilities(self):
        """Initialize available response capabilities"""
        self.response_capabilities = {
            ResponseAction.ISOLATE_HOST: {"available": True, "latency": "2min"},
            ResponseAction.BLOCK_IP: {"available": True, "latency": "30s"},
            ResponseAction.DISABLE_USER: {"available": True, "latency": "1min"},
            ResponseAction.QUARANTINE_FILE: {"available": True, "latency": "1min"},
            ResponseAction.RESET_PASSWORD: {"available": True, "latency": "2min"}
        }

    async def _passes_safety_checks(self, plan: ResponsePlan) -> bool:
        """Check if plan passes safety constraints"""
        try:
            # Check simultaneous operations limit
            active_isolations = sum(1 for p in self.active_responses.values()
                                  if any(a.get("action") == "isolate_host" for a in p.actions))

            new_isolations = sum(1 for a in plan.actions if a.get("action") == "isolate_host")

            if active_isolations + new_isolations > self.safety_constraints["max_simultaneous_isolations"]:
                return False

            # Check critical systems
            if self.safety_constraints["critical_systems_require_approval"]:
                if await self._affects_critical_systems(plan):
                    plan.approval_required = True

            return True

        except Exception as e:
            logging.error(f"Error checking safety constraints: {e}")
            return False

    async def _has_recent_response(self, event: BaseEvent) -> bool:
        """Check if similar response was executed recently"""
        try:
            # Check last 1 hour for similar responses
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

            for plan in self.response_history[-50:]:  # Check recent history
                if (plan.created_at > cutoff and
                    plan.trigger_event and
                    plan.trigger_event.entity_ids == event.entity_ids):
                    return True

            return False

        except Exception as e:
            logging.error(f"Error checking recent responses: {e}")
            return False

    async def _queue_for_approval(self, plan: ResponsePlan):
        """Queue response plan for manual approval"""
        try:
            plan.status = ResponseStatus.PENDING

            # Create approval event
            approval_event = BaseEvent(
                event_type="response_approval_required",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                entity_ids={"plan_id": plan.plan_id},
                message=f"Autonomous response plan requires approval: {plan.incident_id}",
                risk=50,
                enrichment={
                    "plan_details": {
                        "plan_id": plan.plan_id,
                        "urgency": plan.urgency.value,
                        "confidence": plan.confidence,
                        "action_count": len(plan.actions),
                        "estimated_impact": plan.estimated_impact
                    }
                }
            )

            await event_bus.publish(approval_event)
            logging.info(f"Response plan {plan.plan_id} queued for approval")

        except Exception as e:
            logging.error(f"Error queuing plan for approval: {e}")

    async def _create_response_event(self, trigger_event: BaseEvent, plan: ResponsePlan) -> BaseEvent:
        """Create event documenting autonomous response"""
        return BaseEvent(
            event_type="autonomous_response_initiated",
            event_category=EventCategory.AUDIT_ACTIVITY,
            event_class=EventClass.PROCESS_ACTIVITY,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"plan_id": plan.plan_id, "incident_id": plan.incident_id},
            message=f"Autonomous response initiated for incident {plan.incident_id}",
            risk=30,
            confidence=plan.confidence,
            enrichment={
                "response_plan": {
                    "plan_id": plan.plan_id,
                    "urgency": plan.urgency.value,
                    "action_count": len(plan.actions),
                    "auto_execute": plan.auto_execute,
                    "status": plan.status.value
                },
                "trigger_event": {
                    "event_id": trigger_event.event_id,
                    "event_type": trigger_event.event_type,
                    "risk": trigger_event.risk
                }
            }
        )

    async def _is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        now = datetime.now()
        return 9 <= now.hour <= 17 and now.weekday() < 5

    async def _check_system_load(self) -> str:
        """Check current system load"""
        # Simulate system load check
        return "normal"

    async def _identify_critical_systems(self, entity_ids: Dict[str, str]) -> List[str]:
        """Identify critical systems from entity IDs"""
        critical_patterns = ["server", "database", "controller", "gateway"]
        critical_systems = []

        for entity_type, entity_value in entity_ids.items():
            if any(pattern in entity_value.lower() for pattern in critical_patterns):
                critical_systems.append(entity_value)

        return critical_systems

    async def _affects_critical_systems(self, plan: ResponsePlan) -> bool:
        """Check if plan affects critical systems"""
        if not plan.trigger_event:
            return False

        critical_systems = await self._identify_critical_systems(plan.trigger_event.entity_ids)
        return len(critical_systems) > 0

    async def _generate_rollback_plan(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate rollback plan for actions"""
        rollback_plan = []

        for action in reversed(actions):  # Reverse order for rollback
            if action.get("rollback_possible", True):
                rollback_action = await self._create_rollback_action(action)
                if rollback_action:
                    rollback_plan.append(rollback_action)

        return rollback_plan

    async def _create_rollback_action(self, original_action: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create rollback action for original action"""
        action_type = original_action.get("action")

        rollback_mapping = {
            "isolate_host": "restore_host_connectivity",
            "block_ip": "unblock_ip",
            "disable_user": "enable_user",
            "quarantine_file": "restore_file"
        }

        if action_type in rollback_mapping:
            return {
                "id": str(uuid.uuid4()),
                "action": rollback_mapping[action_type],
                "target": original_action.get("target"),
                "original_action_id": original_action.get("id"),
                "priority": 1,
                "parameters": original_action.get("parameters", {}),
                "status": "pending"
            }

        return None

    async def _consider_rollback(self, plan: ResponsePlan, failed_action: Dict[str, Any]):
        """Consider rollback after action failure"""
        try:
            if failed_action.get("priority", 5) <= 2:  # High priority action failed
                logging.warning(f"High priority action failed, considering rollback for plan {plan.plan_id}")

                # Execute rollback if available
                if plan.rollback_plan:
                    await self._execute_rollback(plan)

        except Exception as e:
            logging.error(f"Error considering rollback: {e}")

    async def _execute_rollback(self, plan: ResponsePlan):
        """Execute rollback plan"""
        try:
            logging.info(f"Executing rollback for plan {plan.plan_id}")

            for rollback_action in plan.rollback_plan:
                try:
                    success = await self._execute_action(rollback_action, plan)
                    rollback_action["status"] = "completed" if success else "failed"
                except Exception as e:
                    logging.error(f"Error executing rollback action: {e}")
                    rollback_action["status"] = "error"

            plan.status = ResponseStatus.ROLLED_BACK

        except Exception as e:
            logging.error(f"Error executing rollback: {e}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Cancel any active responses
            for plan_id in list(self.active_responses.keys()):
                plan = self.active_responses[plan_id]
                if plan.status == ResponseStatus.EXECUTING:
                    plan.status = ResponseStatus.FAILED
                    logging.warning(f"Response plan {plan_id} cancelled during shutdown")

            self.active_responses.clear()

            self.logger.info("Autonomous Response Orchestrator cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get orchestrator metrics"""
        return {
            **super().get_metrics(),
            "total_responses": self.metrics.total_responses,
            "successful_responses": self.metrics.successful_responses,
            "failed_responses": self.metrics.failed_responses,
            "success_rate": (self.metrics.successful_responses / max(self.metrics.total_responses, 1)) * 100,
            "auto_executed": self.metrics.auto_executed,
            "manual_approved": self.metrics.manual_approved,
            "avg_response_time": self.metrics.avg_response_time,
            "avg_plan_generation_time": self.metrics.avg_plan_generation_time,
            "active_responses": len(self.active_responses),
            "automation_rules": len(self.automation_rules),
            "response_capabilities": len(self.response_capabilities)
        }


# Global instance
autonomous_response_orchestrator = AutonomousResponseOrchestrator()