"""
SATRIA AI - Log Collector Agent
Collects and normalizes logs from various sources into OCSF format
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


@dataclass
class LogSource:
    """Log source configuration"""
    name: str
    type: str  # syslog, file, api, kafka
    endpoint: str
    auth: Optional[Dict[str, str]] = None
    filters: Optional[List[str]] = None
    enabled: bool = True


class LogCollectorAgent(BaseAgent):
    """
    Priority Agent 1: Log Collector
    Collects logs from various sources and converts to OCSF events
    """

    def __init__(self):
        super().__init__(
            name="log_collector",
            description="Collects and normalizes logs from multiple sources",
            version="1.0.0"
        )
        self.log_sources: List[LogSource] = []
        self.collection_tasks = {}
        self.processed_count = 0
        self.error_count = 0

    async def initialize(self) -> bool:
        """Initialize log collector with configured sources"""
        try:
            # Configure default log sources
            self.log_sources = [
                LogSource(
                    name="syslog",
                    type="syslog",
                    endpoint="udp://0.0.0.0:514",
                    enabled=True
                ),
                LogSource(
                    name="windows_events",
                    type="winlog",
                    endpoint="winlog://Security,System,Application",
                    enabled=True
                ),
                LogSource(
                    name="apache_access",
                    type="file",
                    endpoint="/var/log/apache2/access.log",
                    filters=[".*"],
                    enabled=True
                ),
                LogSource(
                    name="nginx_access",
                    type="file",
                    endpoint="/var/log/nginx/access.log",
                    filters=[".*"],
                    enabled=True
                )
            ]

            # Start collection tasks for enabled sources
            for source in self.log_sources:
                if source.enabled:
                    task = asyncio.create_task(self._collect_from_source(source))
                    self.collection_tasks[source.name] = task

            logging.info(f"Log Collector initialized with {len(self.collection_tasks)} sources")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Log Collector: {e}")
            return False

    async def _collect_from_source(self, source: LogSource):
        """Collect logs from a specific source"""
        logging.info(f"Starting collection from {source.name} ({source.type})")

        while self.is_running:
            try:
                if source.type == "syslog":
                    await self._collect_syslog(source)
                elif source.type == "file":
                    await self._collect_file(source)
                elif source.type == "winlog":
                    await self._collect_winlog(source)
                elif source.type == "api":
                    await self._collect_api(source)

                await asyncio.sleep(1)  # Prevent tight loop

            except Exception as e:
                logging.error(f"Error collecting from {source.name}: {e}")
                self.error_count += 1
                await asyncio.sleep(5)  # Back off on error

    async def _collect_syslog(self, source: LogSource):
        """Collect from syslog UDP"""
        # Simulate syslog collection
        sample_logs = [
            "Sep 19 10:30:15 web01 sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 22 ssh2",
            "Sep 19 10:30:20 web01 kernel: iptables: DROP IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.10",
            "Sep 19 10:30:25 web01 apache2: 192.168.1.50 - - [19/Sep/2025:10:30:25] \"GET /admin/config.php\" 200 1234"
        ]

        for log_line in sample_logs:
            event = await self._parse_syslog_to_event(log_line, source)
            if event:
                await event_bus.publish(event)
                self.processed_count += 1

    async def _collect_file(self, source: LogSource):
        """Collect from log file"""
        # Simulate file tail collection
        sample_entries = [
            '192.168.1.100 - - [19/Sep/2025:10:30:30 +0000] "GET /api/users HTTP/1.1" 200 512',
            '192.168.1.101 - - [19/Sep/2025:10:30:31 +0000] "POST /api/login HTTP/1.1" 401 128',
            '192.168.1.102 - - [19/Sep/2025:10:30:32 +0000] "GET /admin/shell.php HTTP/1.1" 200 2048'
        ]

        for entry in sample_entries:
            event = await self._parse_web_log_to_event(entry, source)
            if event:
                await event_bus.publish(event)
                self.processed_count += 1

    async def _collect_winlog(self, source: LogSource):
        """Collect from Windows Event Log"""
        # Simulate Windows event collection
        sample_events = [
            {
                "EventID": 4624,
                "LogonType": 3,
                "SubjectUserName": "SYSTEM",
                "TargetUserName": "admin",
                "WorkstationName": "WORKSTATION01",
                "SourceNetworkAddress": "192.168.1.100"
            },
            {
                "EventID": 4625,
                "LogonType": 3,
                "SubjectUserName": "SYSTEM",
                "TargetUserName": "administrator",
                "WorkstationName": "WORKSTATION02",
                "SourceNetworkAddress": "10.0.0.100"
            }
        ]

        for win_event in sample_events:
            event = await self._parse_winevent_to_event(win_event, source)
            if event:
                await event_bus.publish(event)
                self.processed_count += 1

    async def _collect_api(self, source: LogSource):
        """Collect from API endpoint"""
        # Placeholder for API collection
        pass

    async def _parse_syslog_to_event(self, log_line: str, source: LogSource) -> Optional[BaseEvent]:
        """Parse syslog line to OCSF event"""
        try:
            # Simple syslog parsing - in production would use proper parser
            parts = log_line.split()
            if len(parts) < 6:
                return None

            timestamp_str = f"{parts[0]} {parts[1]} {parts[2]}"
            hostname = parts[3]
            process = parts[4].split('[')[0] if '[' in parts[4] else parts[4].rstrip(':')
            message = ' '.join(parts[5:])

            # Create base event
            event = BaseEvent(
                event_type="system_activity",
                event_category=EventCategory.SYSTEM_ACTIVITY,
                event_class=EventClass.PROCESS_ACTIVITY,
                timestamp=datetime.now(timezone.utc),
                entity_ids={"host": hostname},
                message=message,
                enrichment={
                    "source": source.name,
                    "process": process,
                    "raw_log": log_line
                }
            )

            # Enhanced parsing for SSH events
            if "sshd" in process and "Accepted" in message:
                event.event_type = "authentication_success"
                event.event_category = EventCategory.IDENTITY_ACCESS_MANAGEMENT
                event.event_class = EventClass.AUTHENTICATION
                event.risk = 10  # Low risk for successful auth

            # Enhanced parsing for firewall drops
            elif "iptables" in message and "DROP" in message:
                event.event_type = "network_blocked"
                event.event_category = EventCategory.NETWORK_ACTIVITY
                event.event_class = EventClass.NETWORK_TRAFFIC
                event.risk = 30  # Medium risk for blocked traffic

            return event

        except Exception as e:
            logging.error(f"Error parsing syslog: {e}")
            return None

    async def _parse_web_log_to_event(self, log_line: str, source: LogSource) -> Optional[BaseEvent]:
        """Parse web access log to OCSF event"""
        try:
            # Simple Apache/Nginx log parsing
            import re
            pattern = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
            match = re.match(pattern, log_line)

            if not match:
                return None

            ip, timestamp_str, method, url, protocol, status, size = match.groups()

            event = BaseEvent(
                event_type="web_request",
                event_category=EventCategory.APPLICATION_ACTIVITY,
                event_class=EventClass.HTTP_ACTIVITY,
                timestamp=datetime.now(timezone.utc),
                entity_ids={"source_ip": ip},
                message=f"{method} {url} {status}",
                enrichment={
                    "source": source.name,
                    "method": method,
                    "url": url,
                    "status_code": int(status),
                    "response_size": size,
                    "raw_log": log_line
                }
            )

            # Risk scoring based on patterns
            risk = 5  # Base risk

            # High risk indicators
            if any(pattern in url.lower() for pattern in ['.php', 'admin', 'config', 'shell']):
                risk += 20
            if int(status) >= 400:
                risk += 15
            if method in ['POST', 'PUT', 'DELETE']:
                risk += 10

            event.risk = min(risk, 100)

            return event

        except Exception as e:
            logging.error(f"Error parsing web log: {e}")
            return None

    async def _parse_winevent_to_event(self, win_event: Dict, source: LogSource) -> Optional[BaseEvent]:
        """Parse Windows event to OCSF event"""
        try:
            event_id = win_event.get('EventID')

            if event_id == 4624:  # Successful logon
                event = BaseEvent(
                    event_type="authentication_success",
                    event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
                    event_class=EventClass.AUTHENTICATION,
                    timestamp=datetime.now(timezone.utc),
                    entity_ids={
                        "user": win_event.get('TargetUserName'),
                        "host": win_event.get('WorkstationName'),
                        "source_ip": win_event.get('SourceNetworkAddress')
                    },
                    message=f"Successful logon for {win_event.get('TargetUserName')}",
                    risk=10,
                    enrichment={
                        "source": source.name,
                        "logon_type": win_event.get('LogonType'),
                        "event_id": event_id
                    }
                )

            elif event_id == 4625:  # Failed logon
                event = BaseEvent(
                    event_type="authentication_failure",
                    event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
                    event_class=EventClass.AUTHENTICATION,
                    timestamp=datetime.now(timezone.utc),
                    entity_ids={
                        "user": win_event.get('TargetUserName'),
                        "host": win_event.get('WorkstationName'),
                        "source_ip": win_event.get('SourceNetworkAddress')
                    },
                    message=f"Failed logon attempt for {win_event.get('TargetUserName')}",
                    risk=40,
                    enrichment={
                        "source": source.name,
                        "logon_type": win_event.get('LogonType'),
                        "event_id": event_id
                    }
                )
            else:
                return None

            return event

        except Exception as e:
            logging.error(f"Error parsing Windows event: {e}")
            return None

    async def process_event(self, event: BaseEvent) -> Optional[BaseEvent]:
        """Process events (not used by collector, but required by base class)"""
        return None

    async def shutdown(self):
        """Shutdown log collector"""
        # Cancel all collection tasks
        for task in self.collection_tasks.values():
            task.cancel()

        await super().shutdown()
        logging.info(f"Log Collector shutdown. Processed: {self.processed_count}, Errors: {self.error_count}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Cancel all collection tasks
            for task in self.collection_tasks.values():
                if not task.done():
                    task.cancel()

            # Clear collections
            self.collection_tasks.clear()
            self.log_sources.clear()

            self.logger.info("Log collector cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get collector metrics"""
        return {
            **super().get_metrics(),
            "processed_logs": self.processed_count,
            "error_count": self.error_count,
            "active_sources": len(self.collection_tasks),
            "configured_sources": len(self.log_sources)
        }


# Global instance
log_collector = LogCollectorAgent()