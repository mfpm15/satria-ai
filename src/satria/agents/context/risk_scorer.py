"""
SATRIA AI - Risk Scoring Agent
Advanced risk scoring using ML models and threat intelligence
"""

import asyncio
import logging
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.context_graph import context_graph


@dataclass
class RiskFeatures:
    """Risk scoring features"""
    temporal_score: float = 0.0
    frequency_score: float = 0.0
    anomaly_score: float = 0.0
    context_score: float = 0.0
    intelligence_score: float = 0.0
    final_score: float = 0.0
    confidence: float = 0.0


class RiskScoringAgent(BaseAgent):
    """
    Priority Agent 3: Risk Scoring
    Advanced risk assessment using ML and threat intelligence
    """

    def __init__(self):
        super().__init__(
            name="risk_scorer",
            description="Advanced risk scoring and threat assessment",
            version="1.0.0"
        )
        self.scored_events = 0
        self.risk_cache = {}
        self.baseline_models = {}
        self.threat_intelligence = {}

        # Risk scoring weights
        self.weights = {
            "temporal": 0.2,
            "frequency": 0.25,
            "anomaly": 0.3,
            "context": 0.15,
            "intelligence": 0.1
        }

    async def initialize(self) -> bool:
        """Initialize risk scoring models and threat intel"""
        try:
            # Load baseline models (in production, these would be trained ML models)
            await self._load_baseline_models()

            # Load threat intelligence feeds
            await self._load_threat_intelligence()

            logging.info("Risk Scoring Agent initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Risk Scorer: {e}")
            return False

    async def _load_baseline_models(self):
        """Load baseline behavioral models"""
        # Mock baseline models - in production these would be trained ML models
        self.baseline_models = {
            "authentication": {
                "normal_hours": list(range(7, 19)),  # 7 AM to 7 PM
                "normal_failure_rate": 0.05,
                "max_attempts_per_hour": 10
            },
            "network": {
                "normal_bandwidth": {"mean": 1000, "std": 500},  # KB/s
                "known_bad_ips": [
                    "185.220.101.182",  # Tor exit node
                    "10.0.0.100",       # Internal suspicious IP
                ],
                "suspicious_ports": [4444, 1337, 31337, 8080]
            },
            "process": {
                "suspicious_processes": [
                    "powershell.exe", "cmd.exe", "wscript.exe",
                    "cscript.exe", "regsvr32.exe", "rundll32.exe"
                ],
                "suspicious_args": [
                    "-enc", "-ExecutionPolicy", "bypass", "downloadstring",
                    "invoke-expression", "iex", "base64"
                ]
            },
            "file": {
                "sensitive_paths": [
                    "/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\config\\SAM",
                    "/var/www/html", "wp-content/uploads"
                ],
                "suspicious_extensions": [".php", ".jsp", ".asp", ".exe", ".scr"]
            }
        }

    async def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        # Mock threat intelligence - in production would connect to MISP, OpenCTI, etc.
        self.threat_intelligence = {
            "malicious_ips": {
                "185.220.101.182": {"type": "tor_exit", "risk": 70},
                "192.168.1.666": {"type": "c2_server", "risk": 95},
                "10.0.0.100": {"type": "compromised_host", "risk": 85}
            },
            "malicious_domains": {
                "malicious.com": {"type": "malware_hosting", "risk": 90},
                "phishing-site.net": {"type": "phishing", "risk": 80}
            },
            "file_hashes": {
                "a1b2c3d4e5f6": {"type": "trojan", "family": "emotet", "risk": 95},
                "f6e5d4c3b2a1": {"type": "ransomware", "family": "ryuk", "risk": 98}
            },
            "attack_patterns": [
                {
                    "name": "credential_stuffing",
                    "indicators": ["high_auth_failures", "multiple_users", "short_timespan"],
                    "risk": 75
                },
                {
                    "name": "lateral_movement",
                    "indicators": ["new_admin_logons", "unusual_network_activity"],
                    "risk": 85
                },
                {
                    "name": "data_exfiltration",
                    "indicators": ["large_data_transfer", "unusual_hours", "external_destination"],
                    "risk": 90
                }
            ]
        }

    async def process_event(self, event: BaseEvent) -> Optional[BaseEvent]:
        """Enhanced risk scoring for events"""
        try:
            # Calculate risk features
            risk_features = await self._calculate_risk_features(event)

            # Apply weighted scoring
            final_risk = self._calculate_final_risk(risk_features)

            # Update event with enhanced risk information
            event.risk = min(int(final_risk), 100)
            event.confidence = risk_features.confidence

            # Add risk analysis to enrichment
            if "risk_analysis" not in event.enrichment:
                event.enrichment["risk_analysis"] = {}

            event.enrichment["risk_analysis"].update({
                "temporal_score": risk_features.temporal_score,
                "frequency_score": risk_features.frequency_score,
                "anomaly_score": risk_features.anomaly_score,
                "context_score": risk_features.context_score,
                "intelligence_score": risk_features.intelligence_score,
                "final_score": final_risk,
                "scoring_version": self.version,
                "scored_at": datetime.now(timezone.utc).isoformat()
            })

            # Add risk-based tags
            await self._add_risk_tags(event, risk_features)

            self.scored_events += 1

            return event

        except Exception as e:
            logging.error(f"Error scoring event {event.event_id}: {e}")
            return event

    async def _calculate_risk_features(self, event: BaseEvent) -> RiskFeatures:
        """Calculate comprehensive risk features"""
        features = RiskFeatures()

        # Temporal scoring - time-based risk
        features.temporal_score = await self._score_temporal(event)

        # Frequency scoring - based on event frequency
        features.frequency_score = await self._score_frequency(event)

        # Anomaly scoring - deviation from baseline
        features.anomaly_score = await self._score_anomaly(event)

        # Context scoring - relationship to other events
        features.context_score = await self._score_context(event)

        # Threat intelligence scoring
        features.intelligence_score = await self._score_intelligence(event)

        # Calculate confidence based on available data
        features.confidence = self._calculate_confidence(features)

        return features

    async def _score_temporal(self, event: BaseEvent) -> float:
        """Score based on temporal patterns"""
        score = 0.0
        current_hour = event.timestamp.hour

        # Higher risk during off-hours
        if event.event_category == EventCategory.IDENTITY_ACCESS_MANAGEMENT:
            normal_hours = self.baseline_models["authentication"]["normal_hours"]
            if current_hour not in normal_hours:
                score += 30.0

        # Higher risk on weekends for business systems
        if event.timestamp.weekday() >= 5:  # Saturday/Sunday
            if any(tag in event.entity_ids.values() for tag in ["server", "workstation"]):
                score += 20.0

        return min(score, 100.0)

    async def _score_frequency(self, event: BaseEvent) -> float:
        """Score based on event frequency patterns"""
        score = 0.0

        try:
            # Get recent similar events from context graph
            similar_events = await self._get_similar_events(event, hours_back=1)

            if event.event_type == "authentication_failure":
                # High frequency auth failures = brute force
                if len(similar_events) > 10:
                    score += 60.0
                elif len(similar_events) > 5:
                    score += 40.0

            elif event.event_type == "network_connection":
                # High frequency network connections to same destination
                same_dest = [e for e in similar_events
                           if e.get("dest_ip") == event.enrichment.get("dest_ip")]
                if len(same_dest) > 100:
                    score += 50.0

        except Exception as e:
            logging.error(f"Error calculating frequency score: {e}")

        return min(score, 100.0)

    async def _score_anomaly(self, event: BaseEvent) -> float:
        """Score based on deviation from normal behavior"""
        score = 0.0

        # Process-based anomalies
        if event.event_class == EventClass.PROCESS_ACTIVITY:
            process_name = event.enrichment.get("process", "")
            command_line = event.enrichment.get("command_line", "")

            # Suspicious processes
            if any(proc in process_name.lower()
                  for proc in self.baseline_models["process"]["suspicious_processes"]):
                score += 40.0

            # Suspicious command line arguments
            if any(arg in command_line.lower()
                  for arg in self.baseline_models["process"]["suspicious_args"]):
                score += 50.0

        # Network-based anomalies
        elif event.event_class == EventClass.NETWORK_TRAFFIC:
            dest_ip = event.enrichment.get("dest_ip")
            dest_port = event.enrichment.get("dest_port")

            # Suspicious destinations
            if dest_ip in self.baseline_models["network"]["known_bad_ips"]:
                score += 70.0

            # Suspicious ports
            if dest_port in self.baseline_models["network"]["suspicious_ports"]:
                score += 30.0

        # File-based anomalies
        elif event.event_class == EventClass.FILE_SYSTEM_ACTIVITY:
            file_path = event.enrichment.get("file_path", "")

            # Access to sensitive paths
            if any(path in file_path
                  for path in self.baseline_models["file"]["sensitive_paths"]):
                score += 60.0

            # Suspicious file extensions
            if any(file_path.lower().endswith(ext)
                  for ext in self.baseline_models["file"]["suspicious_extensions"]):
                score += 40.0

        return min(score, 100.0)

    async def _score_context(self, event: BaseEvent) -> float:
        """Score based on contextual relationships"""
        score = 0.0

        try:
            # Get related events from context graph
            host = event.entity_ids.get("host")
            user = event.entity_ids.get("user")
            source_ip = event.entity_ids.get("source_ip")

            # Check for related high-risk events
            if host:
                related_events = await context_graph.find_related_events(host, hours_back=24)
                high_risk_events = [e for e in related_events if e.get("risk", 0) > 70]
                if len(high_risk_events) > 0:
                    score += 30.0

            # Check for multi-stage attack indicators
            if await self._detect_attack_chain(event):
                score += 50.0

        except Exception as e:
            logging.error(f"Error calculating context score: {e}")

        return min(score, 100.0)

    async def _score_intelligence(self, event: BaseEvent) -> float:
        """Score based on threat intelligence"""
        score = 0.0

        # Check IP addresses
        for ip_field in ["source_ip", "dest_ip"]:
            ip = event.entity_ids.get(ip_field) or event.enrichment.get(ip_field)
            if ip and ip in self.threat_intelligence["malicious_ips"]:
                intel = self.threat_intelligence["malicious_ips"][ip]
                score += intel["risk"] * 0.8

        # Check domains
        domain = event.enrichment.get("domain")
        if domain and domain in self.threat_intelligence["malicious_domains"]:
            intel = self.threat_intelligence["malicious_domains"][domain]
            score += intel["risk"] * 0.9

        # Check file hashes
        file_hash = event.enrichment.get("file_hash")
        if file_hash and file_hash in self.threat_intelligence["file_hashes"]:
            intel = self.threat_intelligence["file_hashes"][file_hash]
            score += intel["risk"]

        return min(score, 100.0)

    def _calculate_final_risk(self, features: RiskFeatures) -> float:
        """Calculate weighted final risk score"""
        final_score = (
            features.temporal_score * self.weights["temporal"] +
            features.frequency_score * self.weights["frequency"] +
            features.anomaly_score * self.weights["anomaly"] +
            features.context_score * self.weights["context"] +
            features.intelligence_score * self.weights["intelligence"]
        )

        return min(final_score, 100.0)

    def _calculate_confidence(self, features: RiskFeatures) -> float:
        """Calculate confidence in risk assessment"""
        # Base confidence
        confidence = 0.5

        # Higher confidence with more features
        feature_count = sum([
            1 if features.temporal_score > 0 else 0,
            1 if features.frequency_score > 0 else 0,
            1 if features.anomaly_score > 0 else 0,
            1 if features.context_score > 0 else 0,
            1 if features.intelligence_score > 0 else 0
        ])

        confidence += (feature_count / 5.0) * 0.4

        return min(confidence, 1.0)

    async def _add_risk_tags(self, event: BaseEvent, features: RiskFeatures):
        """Add risk-based tags to event"""
        if "tags" not in event.enrichment:
            event.enrichment["tags"] = []

        tags = event.enrichment["tags"]

        # Risk level tags
        if features.final_score >= 80:
            tags.append("critical_risk")
        elif features.final_score >= 60:
            tags.append("high_risk")
        elif features.final_score >= 40:
            tags.append("medium_risk")
        else:
            tags.append("low_risk")

        # Feature-specific tags
        if features.intelligence_score > 50:
            tags.append("threat_intel_match")
        if features.context_score > 30:
            tags.append("contextual_risk")
        if features.anomaly_score > 40:
            tags.append("anomalous_behavior")

    async def _get_similar_events(self, event: BaseEvent, hours_back: int = 1) -> List[Dict]:
        """Get similar events from recent history"""
        # Mock implementation - in production would query context graph
        return []

    async def _detect_attack_chain(self, event: BaseEvent) -> bool:
        """Detect if event is part of attack chain"""
        # Mock implementation - in production would use graph analysis
        return False

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Clear scoring cache
            self.scoring_cache.clear()

            # Clear feature data
            if hasattr(self, 'ml_features'):
                self.ml_features.clear()

            self.logger.info("Risk scorer cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get scoring metrics"""
        return {
            **super().get_metrics(),
            "scored_events": self.scored_events,
            "scoring_weights": self.weights,
            "intelligence_sources": len(self.threat_intelligence),
            "baseline_models": list(self.baseline_models.keys())
        }


# Global instance
risk_scorer = RiskScoringAgent()