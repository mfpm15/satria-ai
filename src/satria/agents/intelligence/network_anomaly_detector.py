"""
SATRIA AI - Network Anomaly Detection Agent
Advanced network traffic analysis using deep learning and graph analysis
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scipy.stats import zscore

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.context_graph import context_graph


class NetworkAnomalyType(str, Enum):
    """Types of network anomalies"""
    TRAFFIC_VOLUME = "traffic_volume"
    COMMUNICATION_PATTERN = "communication_pattern"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    TEMPORAL_ANOMALY = "temporal_anomaly"
    GEOGRAPHICAL_ANOMALY = "geographical_anomaly"
    BEACON_DETECTION = "beacon_detection"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class NetworkFlow:
    """Network flow representation"""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration: float
    timestamp: datetime
    flags: List[str] = field(default_factory=list)
    country_src: Optional[str] = None
    country_dst: Optional[str] = None
    asn_src: Optional[str] = None
    asn_dst: Optional[str] = None


@dataclass
class NetworkBaseline:
    """Network baseline for anomaly detection"""
    entity_id: str
    traffic_patterns: Dict[str, Any] = field(default_factory=dict)
    communication_graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    temporal_patterns: Dict[int, float] = field(default_factory=dict)  # hour -> avg traffic
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    port_distribution: Dict[int, float] = field(default_factory=dict)
    geographical_patterns: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sample_count: int = 0


@dataclass
class BeaconCandidate:
    """Potential beacon candidate"""
    source_ip: str
    dest_ip: str
    dest_port: int
    intervals: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    connection_count: int = 0
    regularity_score: float = 0.0
    size_consistency_score: float = 0.0
    confidence_score: float = 0.0


class NetworkAnomalyDetector(BaseAgent):
    """
    Advanced Network Anomaly Detection Agent
    Detects various network-based threats using ML and graph analysis
    """

    def __init__(self):
        super().__init__(
            name="network_anomaly_detector",
            description="Advanced network traffic anomaly detection",
            version="2.0.0"
        )

        self.network_flows: deque = deque(maxlen=100000)  # Keep last 100k flows
        self.network_baselines: Dict[str, NetworkBaseline] = {}
        self.beacon_candidates: Dict[str, BeaconCandidate] = {}
        self.anomalies_detected = 0
        self.flows_processed = 0

        # ML models for different anomaly types
        self.volume_detector = IsolationForest(contamination=0.1, random_state=42)
        self.pattern_detector = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()

        # Analysis parameters
        self.baseline_window = timedelta(days=7)
        self.beacon_analysis_window = timedelta(hours=6)
        self.beacon_min_connections = 5
        self.beacon_regularity_threshold = 0.8
        self.exfiltration_size_threshold = 100 * 1024 * 1024  # 100MB

        # Known malicious indicators
        self.malicious_ports = {22, 23, 135, 445, 1433, 3389, 5985, 5986}
        self.suspicious_protocols = {"icmp", "gre", "esp"}
        self.tor_exit_nodes = set()  # Would be populated from threat intel

    async def initialize(self) -> bool:
        """Initialize network anomaly detector"""
        try:
            # Load network baselines
            await self._load_network_baselines()

            # Initialize threat intelligence
            await self._load_network_threat_intelligence()

            # Start analysis tasks
            asyncio.create_task(self._periodic_beacon_analysis())
            asyncio.create_task(self._periodic_baseline_update())
            asyncio.create_task(self._periodic_graph_analysis())

            logging.info("Network Anomaly Detector initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Network Anomaly Detector: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process network events for anomaly detection"""
        try:
            if event.event_category != EventCategory.NETWORK_ACTIVITY:
                return [event]

            # Extract network flow from event
            flow = self._extract_network_flow(event)
            if not flow:
                return [event]

            self.flows_processed += 1
            self.network_flows.append(flow)

            # Update network baselines
            await self._update_network_baseline(flow)

            # Run various anomaly detection algorithms
            anomalies = []

            # 1. Traffic volume anomalies
            volume_anomaly = await self._detect_volume_anomaly(flow)
            if volume_anomaly:
                anomalies.append(volume_anomaly)

            # 2. Communication pattern anomalies
            pattern_anomaly = await self._detect_pattern_anomaly(flow)
            if pattern_anomaly:
                anomalies.append(pattern_anomaly)

            # 3. Protocol anomalies
            protocol_anomaly = await self._detect_protocol_anomaly(flow)
            if protocol_anomaly:
                anomalies.append(protocol_anomaly)

            # 4. Temporal anomalies
            temporal_anomaly = await self._detect_temporal_anomaly(flow)
            if temporal_anomaly:
                anomalies.append(temporal_anomaly)

            # 5. Geographical anomalies
            geo_anomaly = await self._detect_geographical_anomaly(flow)
            if geo_anomaly:
                anomalies.append(geo_anomaly)

            # 6. Potential beacon traffic
            beacon_candidate = await self._analyze_for_beacons(flow)
            if beacon_candidate:
                anomalies.append({
                    "type": NetworkAnomalyType.BEACON_DETECTION,
                    "confidence": beacon_candidate.confidence_score,
                    "details": {
                        "dest_ip": beacon_candidate.dest_ip,
                        "dest_port": beacon_candidate.dest_port,
                        "regularity_score": beacon_candidate.regularity_score,
                        "connection_count": beacon_candidate.connection_count
                    }
                })

            # 7. Lateral movement detection
            lateral_movement = await self._detect_lateral_movement(flow)
            if lateral_movement:
                anomalies.append(lateral_movement)

            # 8. Data exfiltration detection
            exfiltration = await self._detect_data_exfiltration(flow)
            if exfiltration:
                anomalies.append(exfiltration)

            # Process detected anomalies
            if anomalies:
                await self._process_network_anomalies(event, flow, anomalies)

            return [event]

        except Exception as e:
            logging.error(f"Error in network anomaly detection: {e}")
            return [event]

    def _extract_network_flow(self, event: BaseEvent) -> Optional[NetworkFlow]:
        """Extract network flow from event"""
        try:
            enrichment = event.enrichment

            # Required fields
            source_ip = event.entity_ids.get("source_ip") or enrichment.get("source_ip")
            dest_ip = enrichment.get("dest_ip") or enrichment.get("destination_ip")

            if not source_ip or not dest_ip:
                return None

            flow = NetworkFlow(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=int(enrichment.get("source_port", 0)),
                dest_port=int(enrichment.get("dest_port", 0)),
                protocol=enrichment.get("protocol", "tcp").lower(),
                bytes_sent=int(enrichment.get("bytes_sent", 0)),
                bytes_received=int(enrichment.get("bytes_received", 0)),
                packets_sent=int(enrichment.get("packets_sent", 0)),
                packets_received=int(enrichment.get("packets_received", 0)),
                duration=float(enrichment.get("duration", 0)),
                timestamp=event.timestamp,
                flags=enrichment.get("tcp_flags", []),
                country_src=enrichment.get("country_src"),
                country_dst=enrichment.get("country_dst"),
                asn_src=enrichment.get("asn_src"),
                asn_dst=enrichment.get("asn_dst")
            )

            return flow

        except Exception as e:
            logging.error(f"Error extracting network flow: {e}")
            return None

    async def _detect_volume_anomaly(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect traffic volume anomalies"""
        try:
            baseline_key = f"host:{flow.source_ip}"
            baseline = self.network_baselines.get(baseline_key)

            if not baseline or baseline.sample_count < 100:
                return None

            # Calculate current traffic metrics
            total_bytes = flow.bytes_sent + flow.bytes_received
            current_hour = flow.timestamp.hour

            # Compare with baseline
            avg_hourly_traffic = baseline.temporal_patterns.get(current_hour, 0)
            if avg_hourly_traffic == 0:
                return None

            # Calculate anomaly score using z-score
            recent_flows = [f for f in self.network_flows
                           if f.source_ip == flow.source_ip and
                           f.timestamp.hour == current_hour and
                           (flow.timestamp - f.timestamp).total_seconds() < 3600]

            if len(recent_flows) < 10:
                return None

            recent_bytes = [(f.bytes_sent + f.bytes_received) for f in recent_flows]
            z_score = abs(zscore([total_bytes] + recent_bytes)[0])

            if z_score > 3.0:  # 3 standard deviations
                return {
                    "type": NetworkAnomalyType.TRAFFIC_VOLUME,
                    "confidence": min(0.95, z_score / 5.0),
                    "details": {
                        "current_bytes": total_bytes,
                        "baseline_avg": avg_hourly_traffic,
                        "z_score": z_score,
                        "anomaly_factor": total_bytes / avg_hourly_traffic if avg_hourly_traffic > 0 else 0
                    }
                }

        except Exception as e:
            logging.error(f"Error detecting volume anomaly: {e}")

        return None

    async def _detect_pattern_anomaly(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect communication pattern anomalies"""
        try:
            baseline_key = f"host:{flow.source_ip}"
            baseline = self.network_baselines.get(baseline_key)

            if not baseline or not baseline.communication_graph.nodes():
                return None

            # Check if this destination is new or unusual
            dest_key = f"{flow.dest_ip}:{flow.dest_port}"

            # New destination anomaly
            if not baseline.communication_graph.has_node(flow.dest_ip):
                # Check if it's an internal vs external connection
                is_external = self._is_external_ip(flow.dest_ip)
                is_suspicious_port = flow.dest_port in self.malicious_ports

                if is_external or is_suspicious_port:
                    return {
                        "type": NetworkAnomalyType.COMMUNICATION_PATTERN,
                        "confidence": 0.7 if is_external else 0.5,
                        "details": {
                            "pattern": "new_destination",
                            "dest_ip": flow.dest_ip,
                            "dest_port": flow.dest_port,
                            "is_external": is_external,
                            "is_suspicious_port": is_suspicious_port
                        }
                    }

            # Unusual port for known destination
            if baseline.communication_graph.has_node(flow.dest_ip):
                # Get historical ports for this destination
                edges = baseline.communication_graph.edges(flow.dest_ip, data=True)
                historical_ports = set()
                for _, _, data in edges:
                    historical_ports.update(data.get("ports", []))

                if flow.dest_port not in historical_ports and len(historical_ports) > 0:
                    return {
                        "type": NetworkAnomalyType.COMMUNICATION_PATTERN,
                        "confidence": 0.6,
                        "details": {
                            "pattern": "unusual_port",
                            "dest_ip": flow.dest_ip,
                            "new_port": flow.dest_port,
                            "historical_ports": list(historical_ports)
                        }
                    }

        except Exception as e:
            logging.error(f"Error detecting pattern anomaly: {e}")

        return None

    async def _detect_protocol_anomaly(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect protocol anomalies"""
        try:
            # Suspicious protocol usage
            if flow.protocol in self.suspicious_protocols:
                return {
                    "type": NetworkAnomalyType.PROTOCOL_ANOMALY,
                    "confidence": 0.8,
                    "details": {
                        "protocol": flow.protocol,
                        "reason": "suspicious_protocol"
                    }
                }

            # Protocol-port mismatch
            protocol_port_mapping = {
                "http": [80, 8080, 8000],
                "https": [443, 8443],
                "ssh": [22],
                "ftp": [21, 20],
                "smtp": [25, 587, 465],
                "dns": [53]
            }

            for expected_protocol, expected_ports in protocol_port_mapping.items():
                if (flow.dest_port in expected_ports and
                    flow.protocol != expected_protocol and
                    flow.protocol != "tcp"):  # TCP is generic
                    return {
                        "type": NetworkAnomalyType.PROTOCOL_ANOMALY,
                        "confidence": 0.6,
                        "details": {
                            "expected_protocol": expected_protocol,
                            "actual_protocol": flow.protocol,
                            "port": flow.dest_port,
                            "reason": "protocol_port_mismatch"
                        }
                    }

        except Exception as e:
            logging.error(f"Error detecting protocol anomaly: {e}")

        return None

    async def _detect_temporal_anomaly(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect temporal anomalies"""
        try:
            current_hour = flow.timestamp.hour
            is_weekend = flow.timestamp.weekday() >= 5
            is_off_hours = current_hour < 6 or current_hour > 22

            # Check for unusual timing patterns
            baseline_key = f"host:{flow.source_ip}"
            baseline = self.network_baselines.get(baseline_key)

            if baseline and baseline.temporal_patterns:
                normal_hours = [h for h, traffic in baseline.temporal_patterns.items()
                              if traffic > 0]

                if current_hour not in normal_hours and len(normal_hours) > 0:
                    confidence = 0.8 if is_off_hours else 0.5
                    if is_weekend:
                        confidence += 0.1

                    return {
                        "type": NetworkAnomalyType.TEMPORAL_ANOMALY,
                        "confidence": min(0.95, confidence),
                        "details": {
                            "current_hour": current_hour,
                            "normal_hours": normal_hours,
                            "is_weekend": is_weekend,
                            "is_off_hours": is_off_hours
                        }
                    }

        except Exception as e:
            logging.error(f"Error detecting temporal anomaly: {e}")

        return None

    async def _detect_geographical_anomaly(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect geographical anomalies"""
        try:
            if not flow.country_dst:
                return None

            baseline_key = f"host:{flow.source_ip}"
            baseline = self.network_baselines.get(baseline_key)

            if not baseline or not baseline.geographical_patterns:
                return None

            # Check if destination country is unusual
            if flow.country_dst not in baseline.geographical_patterns:
                # High-risk countries (example list)
                high_risk_countries = {"CN", "RU", "KP", "IR"}

                is_high_risk = flow.country_dst in high_risk_countries
                confidence = 0.8 if is_high_risk else 0.5

                return {
                    "type": NetworkAnomalyType.GEOGRAPHICAL_ANOMALY,
                    "confidence": confidence,
                    "details": {
                        "dest_country": flow.country_dst,
                        "is_high_risk": is_high_risk,
                        "historical_countries": list(baseline.geographical_patterns.keys())
                    }
                }

        except Exception as e:
            logging.error(f"Error detecting geographical anomaly: {e}")

        return None

    async def _analyze_for_beacons(self, flow: NetworkFlow) -> Optional[BeaconCandidate]:
        """Analyze traffic for beacon patterns"""
        try:
            beacon_key = f"{flow.source_ip}->{flow.dest_ip}:{flow.dest_port}"

            candidate = self.beacon_candidates.get(beacon_key)
            if not candidate:
                candidate = BeaconCandidate(
                    source_ip=flow.source_ip,
                    dest_ip=flow.dest_ip,
                    dest_port=flow.dest_port,
                    first_seen=flow.timestamp
                )
                self.beacon_candidates[beacon_key] = candidate

            # Update candidate with new flow data
            candidate.connection_count += 1
            candidate.last_seen = flow.timestamp
            candidate.packet_sizes.append(flow.bytes_sent + flow.bytes_received)

            # Calculate interval if we have previous connection
            if len(candidate.intervals) > 0:
                last_connection = candidate.last_seen - timedelta(
                    seconds=candidate.intervals[-1] if candidate.intervals else 0
                )
                interval = (flow.timestamp - last_connection).total_seconds()
                candidate.intervals.append(interval)

            # Only analyze if we have enough data points
            if candidate.connection_count >= self.beacon_min_connections:
                # Calculate regularity score (coefficient of variation)
                if len(candidate.intervals) > 1:
                    intervals_array = np.array(candidate.intervals)
                    cv = np.std(intervals_array) / np.mean(intervals_array)
                    candidate.regularity_score = max(0, 1 - cv)  # Lower CV = higher regularity

                # Calculate size consistency score
                if len(candidate.packet_sizes) > 1:
                    sizes_array = np.array(candidate.packet_sizes)
                    size_cv = np.std(sizes_array) / np.mean(sizes_array)
                    candidate.size_consistency_score = max(0, 1 - size_cv)

                # Calculate overall confidence
                candidate.confidence_score = (
                    candidate.regularity_score * 0.6 +
                    candidate.size_consistency_score * 0.4
                )

                # Return if confidence is above threshold
                if candidate.confidence_score >= self.beacon_regularity_threshold:
                    return candidate

        except Exception as e:
            logging.error(f"Error analyzing for beacons: {e}")

        return None

    async def _detect_lateral_movement(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect potential lateral movement"""
        try:
            # Look for internal-to-internal connections on admin ports
            if (self._is_internal_ip(flow.source_ip) and
                self._is_internal_ip(flow.dest_ip) and
                flow.dest_port in self.malicious_ports):

                # Check for multiple internal destinations from same source
                recent_internal_flows = [
                    f for f in self.network_flows
                    if (f.source_ip == flow.source_ip and
                        self._is_internal_ip(f.dest_ip) and
                        (flow.timestamp - f.timestamp).total_seconds() < 3600)
                ]

                unique_destinations = len(set(f.dest_ip for f in recent_internal_flows))

                if unique_destinations >= 3:  # Multiple internal targets
                    return {
                        "type": NetworkAnomalyType.LATERAL_MOVEMENT,
                        "confidence": min(0.9, unique_destinations / 10.0),
                        "details": {
                            "source_ip": flow.source_ip,
                            "target_count": unique_destinations,
                            "admin_port": flow.dest_port,
                            "time_window": "1_hour"
                        }
                    }

        except Exception as e:
            logging.error(f"Error detecting lateral movement: {e}")

        return None

    async def _detect_data_exfiltration(self, flow: NetworkFlow) -> Optional[Dict[str, Any]]:
        """Detect potential data exfiltration"""
        try:
            # Large outbound data transfers
            if (flow.bytes_sent > self.exfiltration_size_threshold and
                self._is_external_ip(flow.dest_ip)):

                # Check for sustained large transfers
                similar_flows = [
                    f for f in self.network_flows
                    if (f.source_ip == flow.source_ip and
                        f.dest_ip == flow.dest_ip and
                        f.bytes_sent > self.exfiltration_size_threshold / 2 and
                        (flow.timestamp - f.timestamp).total_seconds() < 3600)
                ]

                if len(similar_flows) >= 2:
                    total_bytes = sum(f.bytes_sent for f in similar_flows)

                    return {
                        "type": NetworkAnomalyType.DATA_EXFILTRATION,
                        "confidence": 0.8,
                        "details": {
                            "dest_ip": flow.dest_ip,
                            "total_bytes_sent": total_bytes,
                            "transfer_count": len(similar_flows),
                            "time_window": "1_hour"
                        }
                    }

        except Exception as e:
            logging.error(f"Error detecting data exfiltration: {e}")

        return None

    async def _process_network_anomalies(self, event: BaseEvent, flow: NetworkFlow,
                                       anomalies: List[Dict[str, Any]]):
        """Process detected network anomalies"""
        try:
            self.anomalies_detected += len(anomalies)

            # Calculate overall risk score
            max_confidence = max(a["confidence"] for a in anomalies)
            risk_score = int(max_confidence * 100)

            # Create network anomaly event
            anomaly_event = BaseEvent(
                event_type="network_anomaly",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                entity_ids={
                    "source_ip": flow.source_ip,
                    "dest_ip": flow.dest_ip
                },
                message=f"Network anomaly detected: {len(anomalies)} patterns identified",
                risk=risk_score,
                confidence=max_confidence,
                enrichment={
                    "original_event_id": event.event_id,
                    "flow_details": {
                        "source_ip": flow.source_ip,
                        "dest_ip": flow.dest_ip,
                        "dest_port": flow.dest_port,
                        "protocol": flow.protocol,
                        "bytes_sent": flow.bytes_sent,
                        "bytes_received": flow.bytes_received
                    },
                    "anomaly_details": anomalies,
                    "anomaly_types": [a["type"] for a in anomalies]
                }
            )

            await event_bus.publish(anomaly_event)

            # Update original event
            if "network_anomaly" not in event.enrichment:
                event.enrichment["network_anomaly"] = {}

            event.enrichment["network_anomaly"].update({
                "detected": True,
                "anomaly_count": len(anomalies),
                "max_confidence": max_confidence,
                "anomaly_types": [a["type"] for a in anomalies]
            })

        except Exception as e:
            logging.error(f"Error processing network anomalies: {e}")

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        private_ranges = ["192.168.", "10.", "172.16.", "127.", "169.254."]
        return any(ip.startswith(range_) for range_ in private_ranges)

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external/public"""
        return not self._is_internal_ip(ip)

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Clear network flow data
            self.network_flows.clear()
            self.network_graph.clear()

            # Clear beacon candidates
            self.beacon_candidates.clear()

            # Clear baselines
            self.network_baselines.clear()

            self.logger.info("Network anomaly detector cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get network anomaly detector metrics"""
        anomaly_types = defaultdict(int)
        for anomaly_list in []:  # Would track anomalies by type
            for anomaly in anomaly_list:
                anomaly_types[anomaly["type"]] += 1

        return {
            **super().get_metrics(),
            "flows_processed": self.flows_processed,
            "anomalies_detected": self.anomalies_detected,
            "active_flows": len(self.network_flows),
            "network_baselines": len(self.network_baselines),
            "beacon_candidates": len(self.beacon_candidates),
            "anomaly_types_detected": dict(anomaly_types)
        }


# Global instance
network_anomaly_detector = NetworkAnomalyDetector()