"""
SATRIA AI - EDR Orchestrator Agent
Automated response orchestration for EDR platforms
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import aiohttp

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class ActionStatus(str, Enum):
    """Action execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ActionType(str, Enum):
    """Types of EDR actions"""
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    COLLECT_EVIDENCE = "collect_evidence"
    SCAN_HOST = "scan_host"
    UPDATE_POLICY = "update_policy"
    CREATE_ALERT = "create_alert"


@dataclass
class EDRAction:
    """EDR orchestration action"""
    action_id: str
    action_type: ActionType
    target_platform: str  # crowdstrike, defender, sentinelone
    target_entity: str    # hostname, file_hash, ip, etc.
    parameters: Dict[str, Any]
    status: ActionStatus
    created_at: datetime
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    approval_required: bool = False
    approved_by: Optional[str] = None
    priority: str = "medium"


class EDROrchestratorAgent(BaseAgent):
    """
    Priority Agent 5: EDR Orchestrator
    Automated response orchestration across EDR platforms
    """

    def __init__(self):
        super().__init__(
            name="edr_orchestrator",
            description="Automated response orchestration for EDR platforms",
            version="1.0.0"
        )
        self.pending_actions: Dict[str, EDRAction] = {}
        self.completed_actions: Dict[str, EDRAction] = {}
        self.actions_executed = 0
        self.actions_failed = 0
        self.session: Optional[aiohttp.ClientSession] = None

        # Platform capabilities mapping
        self.platform_capabilities = {
            "crowdstrike": {
                ActionType.ISOLATE_HOST: True,
                ActionType.QUARANTINE_FILE: True,
                ActionType.KILL_PROCESS: True,
                ActionType.COLLECT_EVIDENCE: True,
                ActionType.SCAN_HOST: True,
                ActionType.UPDATE_POLICY: True
            },
            "defender": {
                ActionType.ISOLATE_HOST: True,
                ActionType.QUARANTINE_FILE: True,
                ActionType.KILL_PROCESS: True,
                ActionType.COLLECT_EVIDENCE: True,
                ActionType.SCAN_HOST: True,
                ActionType.BLOCK_IP: True
            },
            "mock_edr": {
                ActionType.ISOLATE_HOST: True,
                ActionType.QUARANTINE_FILE: True,
                ActionType.KILL_PROCESS: True,
                ActionType.BLOCK_IP: True,
                ActionType.COLLECT_EVIDENCE: True,
                ActionType.SCAN_HOST: True
            }
        }

    async def initialize(self) -> bool:
        """Initialize EDR orchestrator"""
        try:
            # Initialize HTTP session
            self.session = aiohttp.ClientSession()

            # Start action processor
            asyncio.create_task(self._process_pending_actions())

            logging.info("EDR Orchestrator Agent initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize EDR Orchestrator: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> Optional[BaseEvent]:
        """Process events and execute automated responses"""
        try:
            # Only process high-risk events or specific event types
            if event.risk < 70 and event.event_type not in ["edr_detection", "triage_case_created"]:
                return event

            # Generate automated response actions
            actions = await self._generate_response_actions(event)

            # Queue actions for execution
            for action in actions:
                await self._queue_action(action)

            return event

        except Exception as e:
            logging.error(f"Error processing event in EDR orchestrator: {e}")
            return event

    async def _generate_response_actions(self, event: BaseEvent) -> List[EDRAction]:
        """Generate appropriate response actions based on event"""
        actions = []

        try:
            # Get event details
            host = event.entity_ids.get("host")
            source_ip = event.entity_ids.get("source_ip")
            file_path = event.enrichment.get("file_path")
            process_name = event.enrichment.get("process")

            # Critical risk events - immediate containment
            if event.risk >= 90:
                if host:
                    # Isolate compromised host
                    actions.append(self._create_action(
                        ActionType.ISOLATE_HOST,
                        target_entity=host,
                        parameters={"reason": f"Critical risk event: {event.event_type}"},
                        priority="critical",
                        approval_required=False  # Auto-execute for critical
                    ))

                if file_path:
                    # Quarantine malicious file
                    actions.append(self._create_action(
                        ActionType.QUARANTINE_FILE,
                        target_entity=file_path,
                        parameters={"file_path": file_path, "reason": "Malicious file detected"},
                        priority="critical"
                    ))

            # High risk events - controlled response
            elif event.risk >= 70:
                if host:
                    # Collect evidence before taking action
                    actions.append(self._create_action(
                        ActionType.COLLECT_EVIDENCE,
                        target_entity=host,
                        parameters={"evidence_types": ["memory", "processes", "network"]},
                        priority="high"
                    ))

                    # Full system scan
                    actions.append(self._create_action(
                        ActionType.SCAN_HOST,
                        target_entity=host,
                        parameters={"scan_type": "full", "priority": "high"},
                        priority="high"
                    ))

                if process_name and "suspicious" in event.enrichment.get("tags", []):
                    # Kill suspicious process
                    actions.append(self._create_action(
                        ActionType.KILL_PROCESS,
                        target_entity=process_name,
                        parameters={
                            "process_name": process_name,
                            "host": host,
                            "reason": "Suspicious process activity"
                        },
                        priority="high",
                        approval_required=True
                    ))

                if source_ip and self._is_external_ip(source_ip):
                    # Block malicious IP
                    actions.append(self._create_action(
                        ActionType.BLOCK_IP,
                        target_entity=source_ip,
                        parameters={
                            "ip": source_ip,
                            "duration": "24h",
                            "reason": "Malicious activity from external IP"
                        },
                        priority="high"
                    ))

            # Medium risk events - investigative actions
            elif event.risk >= 50:
                if host:
                    # Quick scan
                    actions.append(self._create_action(
                        ActionType.SCAN_HOST,
                        target_entity=host,
                        parameters={"scan_type": "quick", "priority": "medium"},
                        priority="medium"
                    ))

            # Event-type specific actions
            if event.event_type == "webshell_detection":
                if file_path:
                    actions.append(self._create_action(
                        ActionType.QUARANTINE_FILE,
                        target_entity=file_path,
                        parameters={"file_path": file_path, "backup": True},
                        priority="critical"
                    ))

                if host:
                    # Enhanced monitoring for web server
                    actions.append(self._create_action(
                        ActionType.UPDATE_POLICY,
                        target_entity=host,
                        parameters={
                            "policy_update": "enhanced_monitoring",
                            "duration": "72h"
                        },
                        priority="high"
                    ))

            return actions

        except Exception as e:
            logging.error(f"Error generating response actions: {e}")
            return []

    def _create_action(self, action_type: ActionType, target_entity: str,
                      parameters: Dict[str, Any], priority: str = "medium",
                      approval_required: bool = True) -> EDRAction:
        """Create an EDR action"""
        action_id = f"edr-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.pending_actions) + 1:03d}"

        # Determine best platform for this action
        target_platform = self._select_platform_for_action(action_type)

        return EDRAction(
            action_id=action_id,
            action_type=action_type,
            target_platform=target_platform,
            target_entity=target_entity,
            parameters=parameters,
            status=ActionStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            priority=priority,
            approval_required=approval_required
        )

    def _select_platform_for_action(self, action_type: ActionType) -> str:
        """Select best EDR platform for the action"""
        # Simple selection logic - in production would consider agent deployment, capabilities, etc.

        # Prefer CrowdStrike for isolation and quarantine
        if action_type in [ActionType.ISOLATE_HOST, ActionType.QUARANTINE_FILE]:
            if settings.crowdstrike_client_id:
                return "crowdstrike"

        # Prefer Defender for Windows-specific actions
        if action_type in [ActionType.KILL_PROCESS, ActionType.SCAN_HOST]:
            if settings.defender_client_id:
                return "defender"

        # Fallback to mock EDR for demo
        return "mock_edr"

    async def _queue_action(self, action: EDRAction):
        """Queue action for execution"""
        self.pending_actions[action.action_id] = action
        logging.info(f"Queued EDR action {action.action_id}: {action.action_type.value} on {action.target_entity}")

        # Create notification event
        notification_event = BaseEvent(
            event_type="edr_action_queued",
            event_category=EventCategory.APPLICATION_ACTIVITY,
            event_class=EventClass.APPLICATION_LIFECYCLE,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"action_id": action.action_id},
            message=f"EDR action queued: {action.action_type.value}",
            risk=25,
            enrichment={
                "action_details": {
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "target_platform": action.target_platform,
                    "target_entity": action.target_entity,
                    "priority": action.priority,
                    "approval_required": action.approval_required
                }
            }
        )

        await event_bus.publish(notification_event)

    async def _process_pending_actions(self):
        """Process pending actions"""
        while self.is_running:
            try:
                # Get actions ready for execution
                ready_actions = [
                    action for action in self.pending_actions.values()
                    if action.status == ActionStatus.PENDING and
                    (not action.approval_required or action.approved_by)
                ]

                # Sort by priority
                priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                ready_actions.sort(key=lambda x: priority_order.get(x.priority, 3))

                # Execute actions
                for action in ready_actions[:5]:  # Process up to 5 actions at a time
                    await self._execute_action(action)

                await asyncio.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logging.error(f"Error processing pending actions: {e}")
                await asyncio.sleep(30)

    async def _execute_action(self, action: EDRAction):
        """Execute an EDR action"""
        try:
            logging.info(f"Executing EDR action {action.action_id}: {action.action_type.value}")

            action.status = ActionStatus.RUNNING
            action.executed_at = datetime.now(timezone.utc)

            # Route to appropriate platform
            if action.target_platform == "crowdstrike":
                result = await self._execute_crowdstrike_action(action)
            elif action.target_platform == "defender":
                result = await self._execute_defender_action(action)
            else:
                result = await self._execute_mock_action(action)

            # Update action with result
            action.result = result
            action.status = ActionStatus.COMPLETED
            action.completed_at = datetime.now(timezone.utc)
            self.actions_executed += 1

            # Move to completed
            self.completed_actions[action.action_id] = action
            del self.pending_actions[action.action_id]

            logging.info(f"Successfully executed action {action.action_id}")

            # Create completion event
            await self._create_completion_event(action)

        except Exception as e:
            logging.error(f"Failed to execute action {action.action_id}: {e}")
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            action.completed_at = datetime.now(timezone.utc)
            self.actions_failed += 1

    async def _execute_crowdstrike_action(self, action: EDRAction) -> Dict[str, Any]:
        """Execute action on CrowdStrike platform"""
        # Mock implementation - in production would use CrowdStrike API
        await asyncio.sleep(2)  # Simulate API call

        if action.action_type == ActionType.ISOLATE_HOST:
            return {
                "platform": "crowdstrike",
                "action": "contain",
                "device_id": f"cs-device-{action.target_entity}",
                "status": "success",
                "isolation_status": "contained"
            }
        elif action.action_type == ActionType.QUARANTINE_FILE:
            return {
                "platform": "crowdstrike",
                "action": "quarantine",
                "file_path": action.parameters["file_path"],
                "quarantine_id": f"cs-quar-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "status": "success"
            }
        else:
            return {"platform": "crowdstrike", "status": "success", "action": action.action_type.value}

    async def _execute_defender_action(self, action: EDRAction) -> Dict[str, Any]:
        """Execute action on Microsoft Defender platform"""
        # Mock implementation - in production would use Defender API
        await asyncio.sleep(1.5)  # Simulate API call

        if action.action_type == ActionType.ISOLATE_HOST:
            return {
                "platform": "defender",
                "action": "isolate",
                "machine_id": f"def-machine-{action.target_entity}",
                "isolation_type": "full",
                "status": "success"
            }
        elif action.action_type == ActionType.SCAN_HOST:
            return {
                "platform": "defender",
                "action": "scan",
                "scan_id": f"def-scan-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "scan_type": action.parameters.get("scan_type", "quick"),
                "status": "initiated"
            }
        else:
            return {"platform": "defender", "status": "success", "action": action.action_type.value}

    async def _execute_mock_action(self, action: EDRAction) -> Dict[str, Any]:
        """Execute mock action for demonstration"""
        await asyncio.sleep(1)  # Simulate processing

        return {
            "platform": "mock_edr",
            "action": action.action_type.value,
            "target": action.target_entity,
            "parameters": action.parameters,
            "status": "success",
            "execution_time": datetime.now(timezone.utc).isoformat()
        }

    async def _create_completion_event(self, action: EDRAction):
        """Create event for action completion"""
        completion_event = BaseEvent(
            event_type="edr_action_completed",
            event_category=EventCategory.APPLICATION_ACTIVITY,
            event_class=EventClass.APPLICATION_LIFECYCLE,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"action_id": action.action_id},
            message=f"EDR action completed: {action.action_type.value}",
            risk=15,
            enrichment={
                "action_details": {
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "target_platform": action.target_platform,
                    "target_entity": action.target_entity,
                    "status": action.status.value,
                    "execution_time": (action.completed_at - action.executed_at).total_seconds() if action.completed_at and action.executed_at else None,
                    "result": action.result
                }
            }
        )

        await event_bus.publish(completion_event)

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external/public"""
        # Simple check - in production would use proper IP classification
        private_ranges = ["192.168.", "10.", "172.16.", "127.", "169.254."]
        return not any(ip.startswith(range_) for range_ in private_ranges)

    async def approve_action(self, action_id: str, approved_by: str) -> bool:
        """Approve a pending action"""
        if action_id in self.pending_actions:
            action = self.pending_actions[action_id]
            action.approved_by = approved_by
            logging.info(f"Action {action_id} approved by {approved_by}")
            return True
        return False

    async def get_pending_actions(self, priority: Optional[str] = None) -> List[EDRAction]:
        """Get pending actions"""
        actions = list(self.pending_actions.values())
        if priority:
            actions = [a for a in actions if a.priority == priority]
        return sorted(actions, key=lambda x: x.created_at)

    async def get_action_status(self, action_id: str) -> Optional[EDRAction]:
        """Get action status"""
        if action_id in self.pending_actions:
            return self.pending_actions[action_id]
        elif action_id in self.completed_actions:
            return self.completed_actions[action_id]
        return None

    async def shutdown(self):
        """Shutdown EDR orchestrator"""
        if self.session:
            await self.session.close()

        await super().shutdown()
        logging.info(f"EDR Orchestrator shutdown. Executed: {self.actions_executed}, Failed: {self.actions_failed}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Cancel pending actions
            for action_id, task in self.pending_actions.items():
                if not task.done():
                    task.cancel()
                    self.logger.debug(f"Cancelled pending action: {action_id}")

            # Clear collections
            self.pending_actions.clear()
            self.action_history.clear()

            self.logger.info("EDR orchestrator cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get orchestrator metrics"""
        pending_by_priority = {}
        for priority in ["critical", "high", "medium", "low"]:
            count = len([a for a in self.pending_actions.values() if a.priority == priority])
            pending_by_priority[priority] = count

        return {
            **super().get_metrics(),
            "actions_executed": self.actions_executed,
            "actions_failed": self.actions_failed,
            "pending_actions": len(self.pending_actions),
            "completed_actions": len(self.completed_actions),
            "pending_by_priority": pending_by_priority,
            "supported_platforms": list(self.platform_capabilities.keys())
        }


# Global instance
edr_orchestrator = EDROrchestratorAgent()