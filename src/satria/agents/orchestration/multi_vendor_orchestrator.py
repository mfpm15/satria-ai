"""
SATRIA AI - Multi-Vendor Security Orchestrator
Phase 3: Universal integration with various security vendors
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid
import aiohttp
import base64
from urllib.parse import urljoin

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class VendorType(str, Enum):
    """Supported security vendor types"""
    EDR = "edr"
    SIEM = "siem"
    SOAR = "soar"
    FIREWALL = "firewall"
    PROXY = "proxy"
    EMAIL_SECURITY = "email_security"
    CLOUD_SECURITY = "cloud_security"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    THREAT_INTELLIGENCE = "threat_intelligence"
    IAM = "iam"


class VendorName(str, Enum):
    """Specific vendor implementations"""
    # EDR
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    MICROSOFT_DEFENDER = "microsoft_defender"
    CARBON_BLACK = "carbon_black"

    # SIEM
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    IBM_QRADAR = "ibm_qradar"
    AZURE_SENTINEL = "azure_sentinel"

    # SOAR
    PHANTOM = "phantom"
    DEMISTO = "demisto"
    SIEMPLIFY = "siemplify"

    # Firewall
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"
    CHECKPOINT = "checkpoint"

    # Cloud
    AWS_SECURITY_HUB = "aws_security_hub"
    AZURE_SECURITY_CENTER = "azure_security_center"
    GCP_SECURITY_COMMAND = "gcp_security_command"


class ActionStatus(str, Enum):
    """Action execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class VendorConfig:
    """Vendor configuration"""
    vendor_name: VendorName
    vendor_type: VendorType
    base_url: str
    api_key: str
    api_secret: Optional[str] = None
    timeout: int = 30
    rate_limit: int = 100
    enabled: bool = True
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestrationAction:
    """Action to be executed across vendors"""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str = ""
    target_vendors: List[VendorName] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    timeout: int = 60
    retry_count: int = 3
    status: ActionStatus = ActionStatus.PENDING
    results: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class MultiVendorOrchestrator(BaseAgent):
    """
    Phase 3: Multi-Vendor Security Orchestrator
    Universal integration and orchestration across security vendors
    """

    def __init__(self):
        super().__init__(
            name="multi_vendor_orchestrator",
            description="Universal multi-vendor security orchestration",
            version="3.0.0"
        )

        self.vendor_configs: Dict[VendorName, VendorConfig] = {}
        self.vendor_connectors: Dict[VendorName, 'BaseVendorConnector'] = {}
        self.active_actions: Dict[str, OrchestrationAction] = {}
        self.action_history: List[OrchestrationAction] = []

        # Action templates for different vendors
        self.action_templates = {}

        # Rate limiting
        self.rate_limiters: Dict[VendorName, Dict[str, Any]] = {}

    async def initialize(self) -> bool:
        """Initialize multi-vendor orchestrator"""
        try:
            # Load vendor configurations
            await self._load_vendor_configs()

            # Initialize vendor connectors
            await self._initialize_vendor_connectors()

            # Load action templates
            await self._load_action_templates()

            logging.info("Multi-Vendor Orchestrator initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Multi-Vendor Orchestrator: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for multi-vendor orchestration"""
        try:
            # Determine required actions based on event
            actions = await self._plan_multi_vendor_actions(event)

            if not actions:
                return [event]

            # Execute actions across vendors
            execution_results = []
            for action in actions:
                result = await self._execute_orchestration_action(action)
                execution_results.append(result)

            # Create orchestration event
            orchestration_event = await self._create_orchestration_event(event, actions, execution_results)

            return [event, orchestration_event]

        except Exception as e:
            logging.error(f"Error processing event for multi-vendor orchestration: {e}")
            return [event]

    async def _plan_multi_vendor_actions(self, event: BaseEvent) -> List[OrchestrationAction]:
        """Plan multi-vendor actions based on event"""
        try:
            actions = []

            # Use LLM to determine optimal vendor strategy
            vendor_strategy = await self._llm_plan_vendor_strategy(event)

            # Convert strategy to executable actions
            for action_spec in vendor_strategy.get("actions", []):
                action = OrchestrationAction(
                    action_type=action_spec["type"],
                    target_vendors=[VendorName(v) for v in action_spec["vendors"]],
                    parameters=action_spec.get("parameters", {}),
                    priority=action_spec.get("priority", 5),
                    timeout=action_spec.get("timeout", 60)
                )
                actions.append(action)
                self.active_actions[action.action_id] = action

            return actions

        except Exception as e:
            logging.error(f"Error planning multi-vendor actions: {e}")
            return []

    async def _llm_plan_vendor_strategy(self, event: BaseEvent) -> Dict[str, Any]:
        """Use LLM to plan optimal vendor strategy"""
        try:
            system_prompt = """You are SATRIA AI's Multi-Vendor Orchestration Strategist.
Plan optimal security actions across multiple vendor platforms.

Available vendors and capabilities:
- CrowdStrike EDR: host isolation, process termination, file quarantine
- SentinelOne EDR: endpoint protection, rollback, threat hunting
- Splunk SIEM: log analysis, alerting, dashboard creation
- Palo Alto Firewall: IP blocking, URL filtering, rule creation
- Azure Sentinel: cloud security, analytics, incident management

Your response must be JSON:
{
    "strategy": "description",
    "actions": [
        {
            "type": "isolate_host|block_ip|quarantine_file|create_alert|hunt_threat",
            "vendors": ["vendor_names"],
            "parameters": {"key": "value"},
            "priority": 1-10,
            "timeout": 60,
            "reason": "why this action"
        }
    ],
    "coordination": "how actions work together",
    "fallback": "backup plan if primary fails"
}

Consider vendor strengths, avoid duplication, ensure coordination."""

            user_prompt = f"""Security Event Analysis:
Event Type: {event.event_type}
Risk Score: {event.risk}/100
Confidence: {event.confidence}
Affected Systems: {event.entity_ids}
Message: {event.message}

Plan multi-vendor response strategy with specific actions."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt)
            ]

            response = await llm_client.chat_completion(
                messages=messages,
                temperature=0.3,
                max_tokens=1000
            )

            try:
                return json.loads(response.content)
            except json.JSONDecodeError:
                return await self._fallback_vendor_strategy(event)

        except Exception as e:
            logging.error(f"Error generating LLM vendor strategy: {e}")
            return await self._fallback_vendor_strategy(event)

    async def _fallback_vendor_strategy(self, event: BaseEvent) -> Dict[str, Any]:
        """Fallback rule-based vendor strategy"""
        strategy = {
            "strategy": "rule-based fallback response",
            "actions": [],
            "coordination": "sequential execution",
            "fallback": "manual intervention"
        }

        # Rule-based action mapping
        if event.event_type == "malware_detection":
            if event.risk >= 80:
                strategy["actions"] = [
                    {
                        "type": "isolate_host",
                        "vendors": ["crowdstrike", "sentinelone"],
                        "parameters": {"host_id": event.entity_ids.get("host", "")},
                        "priority": 1,
                        "timeout": 120,
                        "reason": "immediate threat containment"
                    },
                    {
                        "type": "quarantine_file",
                        "vendors": ["crowdstrike"],
                        "parameters": {"file_hash": event.entity_ids.get("file_hash", "")},
                        "priority": 2,
                        "timeout": 60,
                        "reason": "prevent malware spread"
                    }
                ]

        elif event.event_type == "network_anomaly":
            strategy["actions"] = [
                {
                    "type": "block_ip",
                    "vendors": ["palo_alto", "fortinet"],
                    "parameters": {"ip_address": event.entity_ids.get("src_ip", "")},
                    "priority": 1,
                    "timeout": 30,
                    "reason": "block suspicious network traffic"
                }
            ]

        return strategy

    async def _execute_orchestration_action(self, action: OrchestrationAction) -> Dict[str, Any]:
        """Execute action across multiple vendors"""
        try:
            action.status = ActionStatus.IN_PROGRESS
            results = {}

            # Execute action on each target vendor
            for vendor_name in action.target_vendors:
                if vendor_name not in self.vendor_connectors:
                    results[vendor_name.value] = {
                        "status": "error",
                        "message": "Vendor connector not available"
                    }
                    continue

                connector = self.vendor_connectors[vendor_name]

                try:
                    result = await self._execute_vendor_action(connector, action)
                    results[vendor_name.value] = result
                except Exception as e:
                    results[vendor_name.value] = {
                        "status": "error",
                        "message": str(e)
                    }

            # Update action status
            action.results = results
            action.completed_at = datetime.now(timezone.utc)

            if all(r.get("status") == "success" for r in results.values()):
                action.status = ActionStatus.COMPLETED
            else:
                action.status = ActionStatus.FAILED

            # Move to history
            self.action_history.append(action)
            if action.action_id in self.active_actions:
                del self.active_actions[action.action_id]

            return {
                "action_id": action.action_id,
                "status": action.status.value,
                "results": results,
                "execution_time": (action.completed_at - action.created_at).total_seconds()
            }

        except Exception as e:
            logging.error(f"Error executing orchestration action: {e}")
            action.status = ActionStatus.FAILED
            return {
                "action_id": action.action_id,
                "status": "error",
                "error": str(e)
            }

    async def _execute_vendor_action(self, connector: 'BaseVendorConnector', action: OrchestrationAction) -> Dict[str, Any]:
        """Execute action on specific vendor"""
        try:
            # Check rate limits
            if not await self._check_rate_limit(connector.vendor_name):
                return {
                    "status": "rate_limited",
                    "message": "Rate limit exceeded"
                }

            # Execute based on action type
            if action.action_type == "isolate_host":
                return await connector.isolate_host(action.parameters)
            elif action.action_type == "block_ip":
                return await connector.block_ip(action.parameters)
            elif action.action_type == "quarantine_file":
                return await connector.quarantine_file(action.parameters)
            elif action.action_type == "create_alert":
                return await connector.create_alert(action.parameters)
            elif action.action_type == "hunt_threat":
                return await connector.hunt_threat(action.parameters)
            else:
                return {
                    "status": "error",
                    "message": f"Unknown action type: {action.action_type}"
                }

        except Exception as e:
            logging.error(f"Error executing vendor action: {e}")
            return {
                "status": "error",
                "message": str(e)
            }

    async def _load_vendor_configs(self):
        """Load vendor configurations"""
        self.vendor_configs = {
            VendorName.CROWDSTRIKE: VendorConfig(
                vendor_name=VendorName.CROWDSTRIKE,
                vendor_type=VendorType.EDR,
                base_url="https://api.crowdstrike.com",
                api_key="mock_crowdstrike_key",
                capabilities=["isolate_host", "quarantine_file", "process_kill"]
            ),
            VendorName.SPLUNK: VendorConfig(
                vendor_name=VendorName.SPLUNK,
                vendor_type=VendorType.SIEM,
                base_url="https://splunk.company.com:8089",
                api_key="mock_splunk_key",
                capabilities=["create_alert", "search_logs", "create_dashboard"]
            ),
            VendorName.PALO_ALTO: VendorConfig(
                vendor_name=VendorName.PALO_ALTO,
                vendor_type=VendorType.FIREWALL,
                base_url="https://firewall.company.com",
                api_key="mock_palo_key",
                capabilities=["block_ip", "create_rule", "url_filtering"]
            )
        }

    async def _initialize_vendor_connectors(self):
        """Initialize vendor-specific connectors"""
        for vendor_name, config in self.vendor_configs.items():
            if not config.enabled:
                continue

            try:
                connector = await self._create_vendor_connector(config)
                if connector:
                    self.vendor_connectors[vendor_name] = connector
                    logging.info(f"Initialized connector for {vendor_name.value}")
            except Exception as e:
                logging.error(f"Failed to initialize connector for {vendor_name.value}: {e}")

    async def _create_vendor_connector(self, config: VendorConfig) -> Optional['BaseVendorConnector']:
        """Create vendor-specific connector"""
        try:
            if config.vendor_name == VendorName.CROWDSTRIKE:
                return CrowdStrikeConnector(config)
            elif config.vendor_name == VendorName.SPLUNK:
                return SplunkConnector(config)
            elif config.vendor_name == VendorName.PALO_ALTO:
                return PaloAltoConnector(config)
            # Add more vendors here
            else:
                return GenericVendorConnector(config)
        except Exception as e:
            logging.error(f"Error creating connector for {config.vendor_name}: {e}")
            return None

    async def _load_action_templates(self):
        """Load action templates for different vendors"""
        self.action_templates = {
            "isolate_host": {
                VendorName.CROWDSTRIKE: {
                    "endpoint": "/devices/entities/devices-actions/v2",
                    "method": "POST",
                    "payload": {
                        "action_name": "contain",
                        "ids": ["{host_id}"]
                    }
                },
                VendorName.SENTINELONE: {
                    "endpoint": "/web/api/v2.1/agents/actions/disconnect",
                    "method": "POST",
                    "payload": {
                        "filter": {"computerName": "{host_id}"}
                    }
                }
            },
            "block_ip": {
                VendorName.PALO_ALTO: {
                    "endpoint": "/restapi/v10.0/Objects/Addresses",
                    "method": "POST",
                    "payload": {
                        "entry": {
                            "@name": "blocked-{ip_address}",
                            "ip-netmask": "{ip_address}"
                        }
                    }
                }
            }
        }

    async def _check_rate_limit(self, vendor_name: VendorName) -> bool:
        """Check vendor rate limits"""
        try:
            if vendor_name not in self.rate_limiters:
                self.rate_limiters[vendor_name] = {
                    "requests": 0,
                    "reset_time": datetime.now(timezone.utc).timestamp() + 3600
                }

            limiter = self.rate_limiters[vendor_name]
            now = datetime.now(timezone.utc).timestamp()

            # Reset if hour passed
            if now > limiter["reset_time"]:
                limiter["requests"] = 0
                limiter["reset_time"] = now + 3600

            # Check limit
            config = self.vendor_configs.get(vendor_name)
            if config and limiter["requests"] >= config.rate_limit:
                return False

            limiter["requests"] += 1
            return True

        except Exception as e:
            logging.error(f"Error checking rate limit: {e}")
            return True  # Allow if check fails

    async def _create_orchestration_event(self, trigger_event: BaseEvent, actions: List[OrchestrationAction], results: List[Dict[str, Any]]) -> BaseEvent:
        """Create event documenting multi-vendor orchestration"""
        return BaseEvent(
            event_type="multi_vendor_orchestration",
            event_category=EventCategory.AUDIT_ACTIVITY,
            event_class=EventClass.PROCESS_ACTIVITY,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"orchestration_id": str(uuid.uuid4())},
            message=f"Multi-vendor orchestration executed for {trigger_event.event_type}",
            risk=20,
            confidence=0.9,
            enrichment={
                "trigger_event": {
                    "event_id": trigger_event.event_id,
                    "event_type": trigger_event.event_type,
                    "risk": trigger_event.risk
                },
                "orchestration": {
                    "action_count": len(actions),
                    "vendors_involved": list(set([v.value for action in actions for v in action.target_vendors])),
                    "execution_results": results
                }
            }
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Get orchestrator metrics"""
        return {
            **super().get_metrics(),
            "connected_vendors": len(self.vendor_connectors),
            "active_actions": len(self.active_actions),
            "total_actions_executed": len(self.action_history),
            "success_rate": len([a for a in self.action_history if a.status == ActionStatus.COMPLETED]) / max(len(self.action_history), 1) * 100,
            "vendor_capabilities": {v.value: len(c.capabilities) for v, c in self.vendor_configs.items()},
            "rate_limits": {v.value: r.get("requests", 0) for v, r in self.rate_limiters.items()}
        }


class BaseVendorConnector:
    """Base class for vendor connectors"""

    def __init__(self, config: VendorConfig):
        self.config = config
        self.vendor_name = config.vendor_name
        self.session = None

    async def initialize(self):
        """Initialize connector"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            headers=self._get_auth_headers()
        )

    async def cleanup(self):
        """Cleanup connector"""
        if self.session:
            await self.session.close()

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }

    async def isolate_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate host - to be implemented by specific connectors"""
        raise NotImplementedError

    async def block_ip(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP - to be implemented by specific connectors"""
        raise NotImplementedError

    async def quarantine_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine file - to be implemented by specific connectors"""
        raise NotImplementedError

    async def create_alert(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert - to be implemented by specific connectors"""
        raise NotImplementedError

    async def hunt_threat(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Hunt threat - to be implemented by specific connectors"""
        raise NotImplementedError


class CrowdStrikeConnector(BaseVendorConnector):
    """CrowdStrike EDR connector"""

    async def isolate_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate host via CrowdStrike"""
        try:
            host_id = parameters.get("host_id")

            # Simulate CrowdStrike API call
            await asyncio.sleep(0.1)

            logging.info(f"CrowdStrike: Isolated host {host_id}")
            return {
                "status": "success",
                "message": f"Host {host_id} isolated successfully",
                "action_id": str(uuid.uuid4())
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    async def quarantine_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine file via CrowdStrike"""
        try:
            file_hash = parameters.get("file_hash")

            await asyncio.sleep(0.1)

            logging.info(f"CrowdStrike: Quarantined file {file_hash}")
            return {
                "status": "success",
                "message": f"File {file_hash} quarantined",
                "quarantine_id": str(uuid.uuid4())
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


class SplunkConnector(BaseVendorConnector):
    """Splunk SIEM connector"""

    async def create_alert(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert in Splunk"""
        try:
            alert_title = parameters.get("title", "SATRIA AI Alert")
            severity = parameters.get("severity", "medium")

            await asyncio.sleep(0.1)

            logging.info(f"Splunk: Created alert '{alert_title}' with severity {severity}")
            return {
                "status": "success",
                "message": f"Alert created: {alert_title}",
                "alert_id": str(uuid.uuid4())
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


class PaloAltoConnector(BaseVendorConnector):
    """Palo Alto Firewall connector"""

    async def block_ip(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP via Palo Alto firewall"""
        try:
            ip_address = parameters.get("ip_address")

            await asyncio.sleep(0.1)

            logging.info(f"Palo Alto: Blocked IP {ip_address}")
            return {
                "status": "success",
                "message": f"IP {ip_address} blocked",
                "rule_id": str(uuid.uuid4())
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


class GenericVendorConnector(BaseVendorConnector):
    """Generic vendor connector for unsupported vendors"""

    async def isolate_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "not_supported", "message": "Host isolation not supported"}

    async def block_ip(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "not_supported", "message": "IP blocking not supported"}

    async def quarantine_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "not_supported", "message": "File quarantine not supported"}

    async def create_alert(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "not_supported", "message": "Alert creation not supported"}

    async def hunt_threat(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "not_supported", "message": "Threat hunting not supported"}


# Global instance
multi_vendor_orchestrator = MultiVendorOrchestrator()