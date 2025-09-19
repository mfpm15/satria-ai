"""
SATRIA AI Log Collector Agent
Perception & Sensing layer - Priority Agent #1

Handles:
- Multi-format log ingestion (Syslog, Windows Event Log, JSON, CEF)
- OCSF/ECS normalization and validation
- Quality scoring and deduplication
- Feature extraction for ML pipeline
- Auto-tagging with CMDB enrichment
"""

import asyncio
import logging
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path

from satria.core.agent_base import PerceptionAgent, AgentConfig
from satria.models.events import BaseEvent, EventCategory, EventClass, Severity, Entity, EntityType
from satria.core.schema_validator import normalizer, validator
from satria.core.event_bus import publish_event
from satria.core.context_graph import context_graph


@dataclass
class LogSource:
    """Log source configuration"""
    name: str
    source_type: str  # syslog, windows_event, json, cef, custom
    connection_string: str
    format_config: Dict[str, Any]
    enabled: bool = True
    priority: int = 5  # 1-10, 10 highest
    quality_threshold: float = 0.8
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class LogEntry:
    """Raw log entry with metadata"""
    source_name: str
    raw_content: str
    timestamp: datetime
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    facility: Optional[str] = None
    severity: Optional[str] = None
    message_hash: str = ""

    def __post_init__(self):
        if not self.message_hash:
            self.message_hash = hashlib.sha256(
                f"{self.raw_content}{self.timestamp}".encode()
            ).hexdigest()[:16]


class LogCollectorAgent(PerceptionAgent):
    """
    SATRIA Log Collector Agent - First Priority Agent

    Responsibilities:
    1. Collect logs from multiple sources (Syslog, WinEvent, JSON, etc.)
    2. Parse and normalize to OCSF/ECS format
    3. Apply quality scoring and deduplication
    4. Extract entities and features
    5. Enrich with CMDB data
    6. Publish to Event Bus and Context Graph
    """

    def __init__(self, config: AgentConfig):
        super().__init__(config)

        # Log source management
        self.log_sources: Dict[str, LogSource] = {}
        self.active_connections: Dict[str, Any] = {}

        # Processing state
        self.processed_hashes: set = set()  # For deduplication
        self.quality_stats = {
            "total_processed": 0,
            "high_quality": 0,
            "medium_quality": 0,
            "low_quality": 0,
            "duplicates_filtered": 0,
            "parsing_errors": 0
        }

        # Parser registry
        self.parsers = {
            "syslog": self._parse_syslog,
            "windows_event": self._parse_windows_event,
            "json": self._parse_json,
            "cef": self._parse_cef,
            "custom": self._parse_custom
        }

        # CMDB cache for enrichment
        self.cmdb_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=1)

        # Feature extractors
        self.feature_extractors = [
            self._extract_network_features,
            self._extract_process_features,
            self._extract_authentication_features,
            self._extract_file_features
        ]

    async def initialize(self) -> bool:
        """Initialize the Log Collector Agent"""
        try:
            # Load log source configurations
            await self._load_log_sources()

            # Initialize connections
            await self._initialize_connections()

            # Setup CMDB cache
            await self._initialize_cmdb_cache()

            # Initialize quality scoring models
            await self._initialize_quality_models()

            self.logger.info(f"Log Collector initialized with {len(self.log_sources)} sources")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Log Collector: {e}")
            return False

    async def _load_log_sources(self) -> None:
        """Load log source configurations"""
        # Example configurations - in production these would come from config files
        default_sources = {
            "syslog_main": LogSource(
                name="syslog_main",
                source_type="syslog",
                connection_string="udp://0.0.0.0:514",
                format_config={"facility_map": "standard", "severity_map": "rfc3164"},
                priority=10,
                tags=["system", "security"]
            ),
            "windows_security": LogSource(
                name="windows_security",
                source_type="windows_event",
                connection_string="winrm://domain-controller:5985/wsman",
                format_config={"channel": "Security", "xpath_filter": "*[System/EventID=4624 or System/EventID=4625]"},
                priority=9,
                tags=["windows", "authentication", "security"]
            ),
            "application_json": LogSource(
                name="application_json",
                source_type="json",
                connection_string="kafka://kafka:9092/app-logs",
                format_config={"timestamp_field": "@timestamp", "message_field": "message"},
                priority=7,
                tags=["application", "json"]
            ),
            "firewall_cef": LogSource(
                name="firewall_cef",
                source_type="cef",
                connection_string="tcp://0.0.0.0:514",
                format_config={"cef_version": "0.1", "device_vendor": "PaloAlto"},
                priority=8,
                tags=["network", "firewall", "security"]
            )
        }

        self.log_sources.update(default_sources)

    async def _initialize_connections(self) -> None:
        """Initialize connections to log sources"""
        for source_name, source in self.log_sources.items():
            if source.enabled:
                try:
                    # In production, create actual connections based on connection_string
                    # For now, simulate connection
                    self.active_connections[source_name] = {
                        "status": "connected",
                        "last_seen": datetime.utcnow(),
                        "message_count": 0
                    }
                    self.logger.info(f"Connected to log source: {source_name}")
                except Exception as e:
                    self.logger.error(f"Failed to connect to {source_name}: {e}")

    async def _initialize_cmdb_cache(self) -> None:
        """Initialize CMDB cache for entity enrichment"""
        # Simulate CMDB data - in production this would query actual CMDB
        self.cmdb_cache = {
            "10.10.1.100": {
                "hostname": "web-server-01",
                "owner": "web-team",
                "criticality": "high",
                "environment": "production",
                "business_unit": "e-commerce"
            },
            "web-server-01": {
                "ip_address": "10.10.1.100",
                "os": "Ubuntu 20.04",
                "role": "web_server",
                "criticality": "high"
            }
        }

    async def _initialize_quality_models(self) -> None:
        """Initialize quality scoring models"""
        # In production, load actual ML models for quality scoring
        self.quality_weights = {
            "completeness": 0.3,      # Required fields present
            "validity": 0.25,         # Data formats valid
            "consistency": 0.2,       # Consistent with patterns
            "timeliness": 0.15,       # Recent timestamp
            "uniqueness": 0.1         # Not a duplicate
        }

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process incoming raw log event"""
        try:
            # This method typically receives raw events to be processed
            # For Log Collector, we mainly generate events from log sources
            return []

        except Exception as e:
            self.logger.error(f"Error processing event {event.event_id}: {e}")
            return []

    async def collect_data(self) -> List[Dict[str, Any]]:
        """Collect raw data from log sources"""
        collected_logs = []

        for source_name, source in self.log_sources.items():
            if not source.enabled:
                continue

            try:
                # Simulate log collection - in production, read from actual sources
                raw_logs = await self._collect_from_source(source)
                collected_logs.extend(raw_logs)

            except Exception as e:
                self.logger.error(f"Error collecting from {source_name}: {e}")

        return collected_logs

    async def _collect_from_source(self, source: LogSource) -> List[Dict[str, Any]]:
        """Collect logs from specific source"""
        # Simulate different log formats
        if source.source_type == "syslog":
            return await self._collect_syslog_sample()
        elif source.source_type == "windows_event":
            return await self._collect_windows_event_sample()
        elif source.source_type == "json":
            return await self._collect_json_sample()
        elif source.source_type == "cef":
            return await self._collect_cef_sample()
        else:
            return []

    async def _collect_syslog_sample(self) -> List[Dict[str, Any]]:
        """Generate sample syslog entries"""
        return [
            {
                "raw_content": "Oct 19 10:15:23 web-server-01 sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2",
                "source": "syslog_main",
                "timestamp": datetime.utcnow(),
                "facility": "auth",
                "severity": "info"
            },
            {
                "raw_content": "Oct 19 10:16:45 web-server-01 nginx: 192.168.1.100 - - [19/Oct/2025:10:16:45 +0000] \"GET /admin/login.php\" 200 1234",
                "source": "syslog_main",
                "timestamp": datetime.utcnow(),
                "facility": "daemon",
                "severity": "info"
            }
        ]

    async def _collect_windows_event_sample(self) -> List[Dict[str, Any]]:
        """Generate sample Windows Event Log entries"""
        return [
            {
                "raw_content": """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                    <System>
                        <EventID>4624</EventID>
                        <Level>0</Level>
                        <Computer>DC-01</Computer>
                        <TimeCreated SystemTime='2025-10-19T10:15:23.123456Z'/>
                    </System>
                    <EventData>
                        <Data Name='SubjectUserName'>administrator</Data>
                        <Data Name='TargetUserName'>user1</Data>
                        <Data Name='IpAddress'>192.168.1.100</Data>
                        <Data Name='LogonType'>2</Data>
                    </EventData>
                </Event>""",
                "source": "windows_security",
                "timestamp": datetime.utcnow()
            }
        ]

    async def _collect_json_sample(self) -> List[Dict[str, Any]]:
        """Generate sample JSON log entries"""
        return [
            {
                "raw_content": json.dumps({
                    "@timestamp": "2025-10-19T10:15:23.123Z",
                    "level": "ERROR",
                    "logger": "com.webapp.auth",
                    "message": "Authentication failed for user: admin",
                    "remote_addr": "192.168.1.100",
                    "user_agent": "Mozilla/5.0...",
                    "request_id": "abc-123-def"
                }),
                "source": "application_json",
                "timestamp": datetime.utcnow()
            }
        ]

    async def _collect_cef_sample(self) -> List[Dict[str, Any]]:
        """Generate sample CEF format entries"""
        return [
            {
                "raw_content": "CEF:0|PaloAlto|PAN-OS|8.1|TRAFFIC|end|3|rt=Oct 19 2025 10:15:23|src=192.168.1.100|dst=10.10.1.100|spt=54321|dpt=80|act=allow",
                "source": "firewall_cef",
                "timestamp": datetime.utcnow()
            }
        ]

    async def normalize_data(self, raw_data: Dict[str, Any]) -> BaseEvent:
        """Normalize raw log data to OCSF/ECS format"""
        try:
            source_name = raw_data.get("source", "unknown")
            source_config = self.log_sources.get(source_name)

            if not source_config:
                self.logger.warning(f"Unknown source: {source_name}")
                source_config = LogSource("unknown", "custom", "", {})

            # Create log entry object
            log_entry = LogEntry(
                source_name=source_name,
                raw_content=raw_data.get("raw_content", ""),
                timestamp=raw_data.get("timestamp", datetime.utcnow()),
                facility=raw_data.get("facility"),
                severity=raw_data.get("severity")
            )

            # Parse based on source type
            parser = self.parsers.get(source_config.source_type, self._parse_custom)
            parsed_data = await parser(log_entry, source_config)

            # Normalize using SATRIA normalizer
            normalized_event = normalizer.normalize_event(parsed_data, source_config.source_type)

            # Calculate quality score
            quality_score = await self._calculate_quality_score(normalized_event, log_entry)
            normalized_event.quality_score = quality_score

            # Extract and enrich entities
            await self._extract_and_enrich_entities(normalized_event, log_entry)

            # Extract features for ML pipeline
            features = await self._extract_features(normalized_event, log_entry)
            normalized_event.enrichment["features"] = features

            # Add source metadata
            normalized_event.enrichment.update({
                "source_name": source_name,
                "source_type": source_config.source_type,
                "source_tags": source_config.tags,
                "processing_timestamp": datetime.utcnow().isoformat()
            })

            return normalized_event

        except Exception as e:
            self.logger.error(f"Error normalizing data: {e}")
            # Return minimal error event
            return BaseEvent(
                event_type="log_processing_error",
                event_category=EventCategory.SYSTEM_ACTIVITY,
                event_class=EventClass.PROCESS_ACTIVITY,
                source_agent=self.agent_name,
                quality_score=0.0,
                needs_review=True,
                enrichment={"error": str(e), "raw_data": str(raw_data)[:1000]}
            )

    async def _parse_syslog(self, log_entry: LogEntry, source_config: LogSource) -> Dict[str, Any]:
        """Parse syslog format"""
        content = log_entry.raw_content

        # Basic syslog parsing - production would use proper syslog parser
        syslog_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)'
        match = re.match(syslog_pattern, content)

        if match:
            timestamp_str, hostname, process, message = match.groups()

            return {
                "timestamp": log_entry.timestamp,
                "source_host": hostname,
                "process_name": process.split('[')[0],
                "message": message,
                "event_type": "syslog_message",
                "event_category": EventCategory.SYSTEM_ACTIVITY,
                "event_class": EventClass.PROCESS_ACTIVITY,
                "severity": log_entry.severity or "info"
            }
        else:
            return {
                "timestamp": log_entry.timestamp,
                "message": content,
                "event_type": "unparsed_syslog",
                "event_category": EventCategory.SYSTEM_ACTIVITY,
                "event_class": EventClass.PROCESS_ACTIVITY
            }

    async def _parse_windows_event(self, log_entry: LogEntry, source_config: LogSource) -> Dict[str, Any]:
        """Parse Windows Event Log XML format"""
        try:
            root = ET.fromstring(log_entry.raw_content)

            # Extract system information
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            event_id = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text
            computer = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text

            # Extract event data
            event_data = {}
            for data in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                name = data.get('Name')
                value = data.text
                if name and value:
                    event_data[name] = value

            # Determine event category based on EventID
            if event_id in ['4624', '4625', '4634']:
                category = EventCategory.IDENTITY_ACCESS_MANAGEMENT
                event_class = EventClass.AUTHENTICATION
                event_type = f"windows_logon_{event_id}"
            else:
                category = EventCategory.SYSTEM_ACTIVITY
                event_class = EventClass.PROCESS_ACTIVITY
                event_type = f"windows_event_{event_id}"

            return {
                "timestamp": log_entry.timestamp,
                "source_host": computer,
                "event_id": event_id,
                "event_type": event_type,
                "event_category": category,
                "event_class": event_class,
                "event_data": event_data,
                "user_id": event_data.get('TargetUserName'),
                "source_ip": event_data.get('IpAddress')
            }

        except ET.ParseError as e:
            self.logger.error(f"Error parsing Windows Event XML: {e}")
            return {
                "timestamp": log_entry.timestamp,
                "message": log_entry.raw_content,
                "event_type": "windows_parse_error",
                "event_category": EventCategory.SYSTEM_ACTIVITY,
                "event_class": EventClass.PROCESS_ACTIVITY
            }

    async def _parse_json(self, log_entry: LogEntry, source_config: LogSource) -> Dict[str, Any]:
        """Parse JSON format logs"""
        try:
            json_data = json.loads(log_entry.raw_content)

            return {
                "timestamp": log_entry.timestamp,
                "message": json_data.get("message", ""),
                "level": json_data.get("level", "info"),
                "logger": json_data.get("logger", ""),
                "source_ip": json_data.get("remote_addr"),
                "user_agent": json_data.get("user_agent"),
                "request_id": json_data.get("request_id"),
                "event_type": "application_log",
                "event_category": EventCategory.APPLICATION_ACTIVITY,
                "event_class": EventClass.APPLICATION_LIFECYCLE
            }

        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing JSON log: {e}")
            return {
                "timestamp": log_entry.timestamp,
                "message": log_entry.raw_content,
                "event_type": "json_parse_error",
                "event_category": EventCategory.SYSTEM_ACTIVITY,
                "event_class": EventClass.PROCESS_ACTIVITY
            }

    async def _parse_cef(self, log_entry: LogEntry, source_config: LogSource) -> Dict[str, Any]:
        """Parse CEF (Common Event Format) logs"""
        content = log_entry.raw_content

        # Basic CEF parsing
        if content.startswith('CEF:'):
            parts = content.split('|')
            if len(parts) >= 7:
                version = parts[0].replace('CEF:', '')
                device_vendor = parts[1]
                device_product = parts[2]
                device_version = parts[3]
                signature_id = parts[4]
                name = parts[5]
                severity = parts[6]

                # Parse extensions
                extensions = {}
                if len(parts) > 7:
                    ext_string = '|'.join(parts[7:])
                    for ext in ext_string.split('|'):
                        if '=' in ext:
                            key, value = ext.split('=', 1)
                            extensions[key] = value

                return {
                    "timestamp": log_entry.timestamp,
                    "device_vendor": device_vendor,
                    "device_product": device_product,
                    "signature_id": signature_id,
                    "name": name,
                    "severity": severity,
                    "source_ip": extensions.get('src'),
                    "destination_ip": extensions.get('dst'),
                    "source_port": extensions.get('spt'),
                    "destination_port": extensions.get('dpt'),
                    "action": extensions.get('act'),
                    "event_type": "cef_security_event",
                    "event_category": EventCategory.NETWORK_ACTIVITY,
                    "event_class": EventClass.NETWORK_CONNECTION_QUERY,
                    "extensions": extensions
                }

        return {
            "timestamp": log_entry.timestamp,
            "message": content,
            "event_type": "cef_parse_error",
            "event_category": EventCategory.SYSTEM_ACTIVITY,
            "event_class": EventClass.PROCESS_ACTIVITY
        }

    async def _parse_custom(self, log_entry: LogEntry, source_config: LogSource) -> Dict[str, Any]:
        """Parse custom format logs"""
        return {
            "timestamp": log_entry.timestamp,
            "message": log_entry.raw_content,
            "event_type": "custom_log",
            "event_category": EventCategory.SYSTEM_ACTIVITY,
            "event_class": EventClass.PROCESS_ACTIVITY
        }

    async def _calculate_quality_score(self, event: BaseEvent, log_entry: LogEntry) -> float:
        """Calculate quality score for normalized event"""
        scores = {}

        # Completeness - check required fields
        required_fields = ['event_type', 'timestamp', 'source_agent']
        present_fields = sum(1 for field in required_fields if hasattr(event, field) and getattr(event, field))
        scores['completeness'] = present_fields / len(required_fields)

        # Validity - check data formats
        validity_score = 1.0
        if event.risk_score is not None and (event.risk_score < 0 or event.risk_score > 100):
            validity_score -= 0.2
        if event.quality_score < 0 or event.quality_score > 1:
            validity_score -= 0.2
        scores['validity'] = max(0.0, validity_score)

        # Consistency - check against patterns
        scores['consistency'] = 0.8  # Simplified - would use ML models in production

        # Timeliness - prefer recent events
        age_hours = (datetime.utcnow() - event.timestamp).total_seconds() / 3600
        scores['timeliness'] = max(0.0, 1.0 - (age_hours / 24))  # Decay over 24 hours

        # Uniqueness - check for duplicates
        is_unique = log_entry.message_hash not in self.processed_hashes
        scores['uniqueness'] = 1.0 if is_unique else 0.0

        if is_unique:
            self.processed_hashes.add(log_entry.message_hash)
            # Keep only last 10000 hashes to prevent memory growth
            if len(self.processed_hashes) > 10000:
                self.processed_hashes = set(list(self.processed_hashes)[-5000:])

        # Weighted average
        quality_score = sum(
            scores[metric] * weight
            for metric, weight in self.quality_weights.items()
        )

        return min(1.0, max(0.0, quality_score))

    async def _extract_and_enrich_entities(self, event: BaseEvent, log_entry: LogEntry) -> None:
        """Extract entities and enrich with CMDB data"""
        entities = []

        # Extract IP addresses
        for field_name in ['source_ip', 'destination_ip', 'remote_addr']:
            if hasattr(event, field_name):
                ip_value = getattr(event, field_name)
                if ip_value:
                    entity = Entity(
                        entity_id=f"ip-{ip_value}",
                        entity_type=EntityType.IP_ADDRESS,
                        name=ip_value,
                        properties=self._enrich_from_cmdb(ip_value)
                    )
                    entities.append(entity)

        # Extract hostnames
        for field_name in ['source_host', 'hostname', 'computer']:
            if hasattr(event, field_name):
                host_value = getattr(event, field_name)
                if host_value:
                    entity = Entity(
                        entity_id=f"host-{host_value}",
                        entity_type=EntityType.DEVICE,
                        name=host_value,
                        properties=self._enrich_from_cmdb(host_value)
                    )
                    entities.append(entity)

        # Extract users
        for field_name in ['user_id', 'username', 'TargetUserName']:
            if hasattr(event, field_name):
                user_value = getattr(event, field_name)
                if user_value:
                    entity = Entity(
                        entity_id=f"user-{user_value}",
                        entity_type=EntityType.USER,
                        name=user_value,
                        properties=self._enrich_from_cmdb(user_value)
                    )
                    entities.append(entity)

        event.entities = entities

    def _enrich_from_cmdb(self, identifier: str) -> Dict[str, Any]:
        """Enrich entity with CMDB data"""
        return self.cmdb_cache.get(identifier, {})

    async def _extract_features(self, event: BaseEvent, log_entry: LogEntry) -> Dict[str, Any]:
        """Extract features for ML pipeline"""
        features = {}

        # Apply all feature extractors
        for extractor in self.feature_extractors:
            try:
                extractor_features = await extractor(event, log_entry)
                features.update(extractor_features)
            except Exception as e:
                self.logger.warning(f"Feature extractor error: {e}")

        return features

    async def _extract_network_features(self, event: BaseEvent, log_entry: LogEntry) -> Dict[str, Any]:
        """Extract network-related features"""
        features = {}

        if hasattr(event, 'source_ip') and event.source_ip:
            features['has_source_ip'] = True
            features['is_private_ip'] = self._is_private_ip(event.source_ip)

        if hasattr(event, 'destination_port') and event.destination_port:
            features['destination_port'] = int(event.destination_port)
            features['is_well_known_port'] = int(event.destination_port) < 1024

        return features

    async def _extract_process_features(self, event: BaseEvent, log_entry: LogEntry) -> Dict[str, Any]:
        """Extract process-related features"""
        features = {}

        if hasattr(event, 'process_name') and event.process_name:
            features['has_process_name'] = True
            features['process_name_length'] = len(event.process_name)
            features['is_system_process'] = event.process_name.lower() in ['svchost.exe', 'explorer.exe', 'winlogon.exe']

        return features

    async def _extract_authentication_features(self, event: BaseEvent, log_entry: LogEntry) -> Dict[str, Any]:
        """Extract authentication-related features"""
        features = {}

        if event.event_category == EventCategory.IDENTITY_ACCESS_MANAGEMENT:
            features['is_auth_event'] = True

            if hasattr(event, 'user_id') and event.user_id:
                features['has_username'] = True
                features['username_length'] = len(event.user_id)
                features['is_admin_user'] = 'admin' in event.user_id.lower()

        return features

    async def _extract_file_features(self, event: BaseEvent, log_entry: LogEntry) -> Dict[str, Any]:
        """Extract file-related features"""
        features = {}

        # Look for file paths in message
        if hasattr(event, 'message') and event.message:
            file_extensions = re.findall(r'\.([a-zA-Z0-9]{1,5})\b', event.message)
            if file_extensions:
                features['has_file_extension'] = True
                features['file_extensions'] = list(set(file_extensions))
                features['executable_file'] = any(ext.lower() in ['exe', 'bat', 'ps1', 'sh'] for ext in file_extensions)

        return features

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    async def cleanup(self) -> None:
        """Cleanup resources"""
        # Close connections
        for connection in self.active_connections.values():
            try:
                # In production, properly close connections
                pass
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")

        self.active_connections.clear()
        self.processed_hashes.clear()

        self.logger.info("Log Collector Agent cleanup completed")

    async def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            **self.quality_stats,
            "active_sources": len([s for s in self.log_sources.values() if s.enabled]),
            "active_connections": len(self.active_connections),
            "processed_hashes_count": len(self.processed_hashes),
            "cmdb_cache_size": len(self.cmdb_cache)
        }

    async def run_processing_cycle(self) -> None:
        """Run one processing cycle - collect, normalize, and publish"""
        try:
            # Collect raw logs
            raw_logs = await self.collect_data()

            if not raw_logs:
                return

            events_to_publish = []

            for raw_log in raw_logs:
                try:
                    # Normalize log to OCSF event
                    normalized_event = await self.normalize_data(raw_log)

                    # Update quality stats
                    self.quality_stats["total_processed"] += 1
                    if normalized_event.quality_score >= 0.8:
                        self.quality_stats["high_quality"] += 1
                    elif normalized_event.quality_score >= 0.6:
                        self.quality_stats["medium_quality"] += 1
                    else:
                        self.quality_stats["low_quality"] += 1

                    # Check quality threshold
                    source_name = raw_log.get("source", "unknown")
                    source_config = self.log_sources.get(source_name)
                    quality_threshold = source_config.quality_threshold if source_config else 0.8

                    if normalized_event.quality_score >= quality_threshold:
                        events_to_publish.append(normalized_event)
                    else:
                        normalized_event.needs_review = True
                        events_to_publish.append(normalized_event)

                except Exception as e:
                    self.logger.error(f"Error processing log entry: {e}")
                    self.quality_stats["parsing_errors"] += 1

            # Publish events to Event Bus
            for event in events_to_publish:
                await publish_event(event)

                # Add to Context Graph if high quality
                if event.quality_score >= 0.8:
                    await context_graph.add_event_to_graph(event)

            self.logger.info(f"Processed {len(raw_logs)} logs, published {len(events_to_publish)} events")

        except Exception as e:
            self.logger.error(f"Error in processing cycle: {e}")


# Agent factory function
def create_log_collector_agent() -> LogCollectorAgent:
    """Create Log Collector Agent with default configuration"""
    config = AgentConfig(
        agent_id="log-collector-001",
        agent_name="Log Collector Agent",
        agent_type="perception",
        version="1.0.0",
        enabled=True,
        log_level="INFO",
        heartbeat_interval=30,
        max_concurrent_tasks=10,
        config={
            "quality_threshold": 0.8,
            "dedup_window_hours": 1,
            "max_events_per_cycle": 1000,
            "cmdb_cache_ttl_hours": 1
        }
    )

    return LogCollectorAgent(config)