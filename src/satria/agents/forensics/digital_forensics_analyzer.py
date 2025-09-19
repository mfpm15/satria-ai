"""
SATRIA AI - Digital Forensics Analyzer
Phase 3: Advanced forensic analysis and evidence collection
"""

import asyncio
import logging
import json
import hashlib
import os
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid
import zipfile
import tempfile
from pathlib import Path

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class EvidenceType(str, Enum):
    """Types of digital evidence"""
    FILE_SYSTEM = "file_system"
    MEMORY_DUMP = "memory_dump"
    NETWORK_PACKET = "network_packet"
    REGISTRY = "registry"
    EVENT_LOG = "event_log"
    PROCESS_DUMP = "process_dump"
    DISK_IMAGE = "disk_image"
    BROWSER_ARTIFACT = "browser_artifact"
    EMAIL_ARTIFACT = "email_artifact"
    DATABASE_DUMP = "database_dump"


class ForensicTechnique(str, Enum):
    """Forensic analysis techniques"""
    HASH_ANALYSIS = "hash_analysis"
    TIMELINE_ANALYSIS = "timeline_analysis"
    STRING_EXTRACTION = "string_extraction"
    METADATA_EXTRACTION = "metadata_extraction"
    SIGNATURE_ANALYSIS = "signature_analysis"
    ENTROPY_ANALYSIS = "entropy_analysis"
    YARA_SCANNING = "yara_scanning"
    VOLATILITY_ANALYSIS = "volatility_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


class EvidenceState(str, Enum):
    """Evidence processing state"""
    COLLECTED = "collected"
    PROCESSING = "processing"
    ANALYZED = "analyzed"
    PRESERVED = "preserved"
    CORRUPTED = "corrupted"


@dataclass
class ForensicEvidence:
    """Digital forensic evidence"""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType = EvidenceType.FILE_SYSTEM
    source_path: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    file_hash: str = ""
    file_size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    state: EvidenceState = EvidenceState.COLLECTED
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    preservation_path: Optional[str] = None


@dataclass
class ForensicCase:
    """Forensic investigation case"""
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    case_name: str = ""
    investigator: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_items: List[ForensicEvidence] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "active"


class DigitalForensicsAnalyzer(BaseAgent):
    """
    Phase 3: Digital Forensics Analyzer
    Advanced forensic analysis and evidence collection capabilities
    """

    def __init__(self):
        super().__init__(
            name="digital_forensics_analyzer",
            description="Digital forensics analysis and evidence collection",
            version="3.0.0"
        )

        self.active_cases: Dict[str, ForensicCase] = {}
        self.evidence_vault: Dict[str, ForensicEvidence] = {}
        self.forensic_tools: Dict[str, Any] = {}
        self.yara_rules: List[str] = []

        # Forensic workspace
        self.workspace_path = "/tmp/satria_forensics"
        self.evidence_path = "/tmp/satria_evidence"

    async def initialize(self) -> bool:
        """Initialize digital forensics analyzer"""
        try:
            # Setup forensic workspace
            await self._setup_workspace()

            # Initialize forensic tools
            await self._initialize_forensic_tools()

            # Load YARA rules
            await self._load_yara_rules()

            logging.info("Digital Forensics Analyzer initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Digital Forensics Analyzer: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for forensic analysis"""
        try:
            # Check if event requires forensic analysis
            if not await self._requires_forensic_analysis(event):
                return [event]

            # Create or get existing forensic case
            case = await self._get_or_create_case(event)

            # Collect evidence based on event
            evidence_items = await self._collect_evidence(event, case)

            # Perform forensic analysis
            analysis_results = []
            for evidence in evidence_items:
                result = await self._analyze_evidence(evidence, case)
                analysis_results.append(result)

            # Update case timeline
            await self._update_case_timeline(case, event, evidence_items)

            # Generate forensic report event
            forensic_event = await self._create_forensic_event(event, case, analysis_results)

            return [event, forensic_event]

        except Exception as e:
            logging.error(f"Error processing event for forensic analysis: {e}")
            return [event]

    async def _requires_forensic_analysis(self, event: BaseEvent) -> bool:
        """Determine if event requires forensic analysis"""
        forensic_triggers = [
            "malware_detection",
            "data_exfiltration",
            "insider_threat",
            "advanced_persistent_threat",
            "ransomware",
            "credential_theft",
            "system_compromise",
            "suspicious_process"
        ]

        return (
            event.event_type in forensic_triggers or
            (event.risk_score or 0) >= 80 or
            "forensic" in event.enrichment.get("message", "").lower()
        )

    async def _get_or_create_case(self, event: BaseEvent) -> ForensicCase:
        """Get existing or create new forensic case"""
        try:
            # Check for existing case based on incident
            entity_ids = event.enrichment.get("entity_ids", {})
            incident_id = entity_ids.get("incident_id", f"INC-{event.event_id[:8]}")

            for case in self.active_cases.values():
                if case.incident_id == incident_id:
                    return case

            # Create new case
            case = ForensicCase(
                incident_id=incident_id,
                case_name=f"Investigation: {event.event_type}",
                investigator="SATRIA AI Forensics",
            )

            self.active_cases[case.case_id] = case
            logging.info(f"Created new forensic case: {case.case_id}")

            return case

        except Exception as e:
            logging.error(f"Error creating forensic case: {e}")
            raise

    async def _collect_evidence(self, event: BaseEvent, case: ForensicCase) -> List[ForensicEvidence]:
        """Collect digital evidence based on event"""
        try:
            evidence_items = []

            # Determine evidence collection strategy
            collection_plan = await self._plan_evidence_collection(event)

            for evidence_spec in collection_plan:
                try:
                    evidence = await self._collect_evidence_item(evidence_spec, event)
                    if evidence:
                        evidence_items.append(evidence)
                        case.evidence_items.append(evidence)
                        self.evidence_vault[evidence.evidence_id] = evidence
                except Exception as e:
                    logging.error(f"Error collecting evidence {evidence_spec}: {e}")

            return evidence_items

        except Exception as e:
            logging.error(f"Error collecting evidence: {e}")
            return []

    async def _plan_evidence_collection(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Plan evidence collection strategy"""
        try:
            collection_plan = []

            entity_ids = event.enrichment.get("entity_ids", {})

            # File-based evidence
            if "file_path" in entity_ids or "file_hash" in entity_ids:
                collection_plan.append({
                    "type": EvidenceType.FILE_SYSTEM,
                    "target": entity_ids.get("file_path", ""),
                    "hash": entity_ids.get("file_hash", ""),
                    "priority": 1
                })

            # Process-based evidence
            if "process_id" in entity_ids or "process_name" in entity_ids:
                collection_plan.append({
                    "type": EvidenceType.PROCESS_DUMP,
                    "target": entity_ids.get("process_id", ""),
                    "process_name": entity_ids.get("process_name", ""),
                    "priority": 2
                })

            # Network-based evidence
            if "src_ip" in entity_ids or "dst_ip" in entity_ids:
                collection_plan.append({
                    "type": EvidenceType.NETWORK_PACKET,
                    "src_ip": entity_ids.get("src_ip", ""),
                    "dst_ip": entity_ids.get("dst_ip", ""),
                    "priority": 3
                })

            # Host-based evidence
            if "host" in entity_ids:
                collection_plan.extend([
                    {
                        "type": EvidenceType.EVENT_LOG,
                        "target": entity_ids.get("host", ""),
                        "priority": 2
                    },
                    {
                        "type": EvidenceType.REGISTRY,
                        "target": entity_ids.get("host", ""),
                        "priority": 3
                    }
                ])

            return sorted(collection_plan, key=lambda x: x.get("priority", 5))

        except Exception as e:
            logging.error(f"Error planning evidence collection: {e}")
            return []

    async def _collect_evidence_item(self, evidence_spec: Dict[str, Any], event: BaseEvent) -> Optional[ForensicEvidence]:
        """Collect individual evidence item"""
        try:
            evidence_type = EvidenceType(evidence_spec["type"])

            evidence = ForensicEvidence(
                evidence_type=evidence_type,
                source_path=evidence_spec.get("target", ""),
            )

            # Add chain of custody
            evidence.chain_of_custody.append({
                "action": "collected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent": "SATRIA AI Forensics",
                "event_id": event.event_id
            })

            # Collect based on type
            if evidence_type == EvidenceType.FILE_SYSTEM:
                await self._collect_file_evidence(evidence, evidence_spec)
            elif evidence_type == EvidenceType.PROCESS_DUMP:
                await self._collect_process_evidence(evidence, evidence_spec)
            elif evidence_type == EvidenceType.NETWORK_PACKET:
                await self._collect_network_evidence(evidence, evidence_spec)
            elif evidence_type == EvidenceType.EVENT_LOG:
                await self._collect_log_evidence(evidence, evidence_spec)
            elif evidence_type == EvidenceType.REGISTRY:
                await self._collect_registry_evidence(evidence, evidence_spec)

            # Calculate file hash if not provided
            if evidence.preservation_path and not evidence.file_hash:
                evidence.file_hash = await self._calculate_file_hash(evidence.preservation_path)
                evidence.file_size = os.path.getsize(evidence.preservation_path)

            evidence.state = EvidenceState.PRESERVED
            logging.info(f"Collected evidence: {evidence.evidence_id} ({evidence_type.value})")

            return evidence

        except Exception as e:
            logging.error(f"Error collecting evidence item: {e}")
            return None

    async def _collect_file_evidence(self, evidence: ForensicEvidence, spec: Dict[str, Any]):
        """Collect file system evidence"""
        try:
            source_path = spec.get("target", "")
            if not source_path:
                return

            # Simulate file collection (in production, would interface with EDR)
            evidence_filename = f"{evidence.evidence_id}_file.bin"
            preservation_path = os.path.join(self.evidence_path, evidence_filename)

            # Simulate file preservation
            with open(preservation_path, "wb") as f:
                f.write(b"Simulated file evidence content")

            evidence.preservation_path = preservation_path
            evidence.metadata = {
                "original_path": source_path,
                "collection_method": "simulated_edr_pull",
                "file_type": "unknown"
            }

        except Exception as e:
            logging.error(f"Error collecting file evidence: {e}")

    async def _collect_process_evidence(self, evidence: ForensicEvidence, spec: Dict[str, Any]):
        """Collect process memory evidence"""
        try:
            process_id = spec.get("target", "")
            process_name = spec.get("process_name", "")

            evidence_filename = f"{evidence.evidence_id}_process.dmp"
            preservation_path = os.path.join(self.evidence_path, evidence_filename)

            # Simulate process dump
            with open(preservation_path, "wb") as f:
                f.write(b"Simulated process memory dump")

            evidence.preservation_path = preservation_path
            evidence.metadata = {
                "process_id": process_id,
                "process_name": process_name,
                "collection_method": "memory_dump",
                "dump_type": "full"
            }

        except Exception as e:
            logging.error(f"Error collecting process evidence: {e}")

    async def _collect_network_evidence(self, evidence: ForensicEvidence, spec: Dict[str, Any]):
        """Collect network packet evidence"""
        try:
            src_ip = spec.get("src_ip", "")
            dst_ip = spec.get("dst_ip", "")

            evidence_filename = f"{evidence.evidence_id}_network.pcap"
            preservation_path = os.path.join(self.evidence_path, evidence_filename)

            # Simulate packet capture
            with open(preservation_path, "wb") as f:
                f.write(b"Simulated network packet capture")

            evidence.preservation_path = preservation_path
            evidence.metadata = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "collection_method": "packet_capture",
                "protocol": "tcp"
            }

        except Exception as e:
            logging.error(f"Error collecting network evidence: {e}")

    async def _collect_log_evidence(self, evidence: ForensicEvidence, spec: Dict[str, Any]):
        """Collect event log evidence"""
        try:
            host = spec.get("target", "")

            evidence_filename = f"{evidence.evidence_id}_logs.json"
            preservation_path = os.path.join(self.evidence_path, evidence_filename)

            # Simulate log collection
            log_data = {
                "host": host,
                "logs": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_id": "4624",
                        "description": "Successful logon",
                        "user": "suspicious_user"
                    }
                ]
            }

            with open(preservation_path, "w") as f:
                json.dump(log_data, f, indent=2)

            evidence.preservation_path = preservation_path
            evidence.metadata = {
                "host": host,
                "log_types": ["security", "system", "application"],
                "collection_method": "wmi_query"
            }

        except Exception as e:
            logging.error(f"Error collecting log evidence: {e}")

    async def _collect_registry_evidence(self, evidence: ForensicEvidence, spec: Dict[str, Any]):
        """Collect Windows registry evidence"""
        try:
            host = spec.get("target", "")

            evidence_filename = f"{evidence.evidence_id}_registry.reg"
            preservation_path = os.path.join(self.evidence_path, evidence_filename)

            # Simulate registry collection
            with open(preservation_path, "w") as f:
                f.write("Windows Registry Editor Version 5.00\n")
                f.write("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Suspicious]\n")
                f.write('"MaliciousValue"="suspicious_data"\n')

            evidence.preservation_path = preservation_path
            evidence.metadata = {
                "host": host,
                "registry_hives": ["HKLM", "HKCU"],
                "collection_method": "remote_registry"
            }

        except Exception as e:
            logging.error(f"Error collecting registry evidence: {e}")

    async def _analyze_evidence(self, evidence: ForensicEvidence, case: ForensicCase) -> Dict[str, Any]:
        """Perform forensic analysis on evidence"""
        try:
            analysis_results = {
                "evidence_id": evidence.evidence_id,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "techniques_used": [],
                "findings": [],
                "iocs": [],
                "confidence": 0.0
            }

            # Perform different analysis based on evidence type
            if evidence.evidence_type == EvidenceType.FILE_SYSTEM:
                results = await self._analyze_file_evidence(evidence)
                analysis_results.update(results)

            elif evidence.evidence_type == EvidenceType.PROCESS_DUMP:
                results = await self._analyze_process_evidence(evidence)
                analysis_results.update(results)

            elif evidence.evidence_type == EvidenceType.NETWORK_PACKET:
                results = await self._analyze_network_evidence(evidence)
                analysis_results.update(results)

            # Use AI for pattern analysis
            ai_analysis = await self._ai_analyze_evidence(evidence, analysis_results)
            analysis_results["ai_insights"] = ai_analysis

            # Store analysis results
            evidence.analysis_results = analysis_results
            evidence.state = EvidenceState.ANALYZED

            return analysis_results

        except Exception as e:
            logging.error(f"Error analyzing evidence: {e}")
            return {}

    async def _analyze_file_evidence(self, evidence: ForensicEvidence) -> Dict[str, Any]:
        """Analyze file system evidence"""
        try:
            results = {
                "techniques_used": [ForensicTechnique.HASH_ANALYSIS, ForensicTechnique.SIGNATURE_ANALYSIS],
                "findings": []
            }

            if not evidence.preservation_path:
                return results

            # File hash analysis
            file_hash = evidence.file_hash or await self._calculate_file_hash(evidence.preservation_path)
            results["file_hash"] = file_hash

            # File signature analysis
            signature = await self._analyze_file_signature(evidence.preservation_path)
            results["file_signature"] = signature

            # String extraction
            strings = await self._extract_strings(evidence.preservation_path)
            results["interesting_strings"] = strings[:10]  # Top 10

            # Entropy analysis
            entropy = await self._calculate_entropy(evidence.preservation_path)
            results["entropy"] = entropy

            # YARA scanning
            yara_matches = await self._yara_scan(evidence.preservation_path)
            results["yara_matches"] = yara_matches

            # Generate findings
            if entropy > 7.5:
                results["findings"].append({
                    "finding": "High entropy detected",
                    "confidence": 0.8,
                    "severity": "medium"
                })

            if yara_matches:
                results["findings"].append({
                    "finding": f"YARA matches: {', '.join(yara_matches)}",
                    "confidence": 0.9,
                    "severity": "high"
                })

            return results

        except Exception as e:
            logging.error(f"Error analyzing file evidence: {e}")
            return {}

    async def _analyze_process_evidence(self, evidence: ForensicEvidence) -> Dict[str, Any]:
        """Analyze process memory evidence"""
        try:
            results = {
                "techniques_used": [ForensicTechnique.VOLATILITY_ANALYSIS, ForensicTechnique.STRING_EXTRACTION],
                "findings": []
            }

            # Simulate Volatility analysis
            results["process_info"] = {
                "name": evidence.metadata.get("process_name", "unknown"),
                "pid": evidence.metadata.get("process_id", "0"),
                "parent_pid": "4",
                "command_line": "suspicious.exe --hide"
            }

            # Network connections
            results["network_connections"] = [
                {"local_addr": "192.168.1.100:443", "remote_addr": "malicious.com:80", "state": "ESTABLISHED"}
            ]

            # Loaded modules
            results["loaded_modules"] = [
                {"name": "ntdll.dll", "base": "0x7c900000", "size": "0x122000"},
                {"name": "suspicious.dll", "base": "0x10000000", "size": "0x50000"}
            ]

            # Findings
            if "suspicious" in results["process_info"]["command_line"]:
                results["findings"].append({
                    "finding": "Suspicious command line arguments",
                    "confidence": 0.7,
                    "severity": "medium"
                })

            return results

        except Exception as e:
            logging.error(f"Error analyzing process evidence: {e}")
            return {}

    async def _analyze_network_evidence(self, evidence: ForensicEvidence) -> Dict[str, Any]:
        """Analyze network packet evidence"""
        try:
            results = {
                "techniques_used": [ForensicTechnique.NETWORK_ANALYSIS],
                "findings": []
            }

            # Simulate packet analysis
            results["packet_stats"] = {
                "total_packets": 1250,
                "tcp_packets": 980,
                "udp_packets": 200,
                "suspicious_packets": 50
            }

            # Protocol distribution
            results["protocols"] = {
                "HTTP": 45,
                "HTTPS": 35,
                "DNS": 15,
                "OTHER": 5
            }

            # Suspicious indicators
            results["suspicious_domains"] = ["malicious.com", "evil.net"]
            results["c2_indicators"] = ["Beacon activity detected"]

            # Findings
            if results["suspicious_domains"]:
                results["findings"].append({
                    "finding": f"Communication with suspicious domains: {', '.join(results['suspicious_domains'])}",
                    "confidence": 0.8,
                    "severity": "high"
                })

            return results

        except Exception as e:
            logging.error(f"Error analyzing network evidence: {e}")
            return {}

    async def _ai_analyze_evidence(self, evidence: ForensicEvidence, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze evidence patterns"""
        try:
            system_prompt = """You are SATRIA AI's Digital Forensics Expert.
Analyze forensic evidence and provide expert insights.

Provide analysis in JSON format:
{
    "summary": "brief summary of findings",
    "threat_assessment": "threat level and type",
    "attack_techniques": ["MITRE ATT&CK techniques"],
    "recommendations": ["forensic recommendations"],
    "confidence": 0.0-1.0
}

Consider: evidence type, hash indicators, network patterns, process behavior."""

            user_prompt = f"""Forensic Evidence Analysis:

Evidence Type: {evidence.evidence_type.value}
Source: {evidence.source_path}
Hash: {evidence.file_hash}
Metadata: {json.dumps(evidence.metadata, indent=2)}

Analysis Results: {json.dumps(analysis_results, indent=2)}

Provide expert forensic analysis and recommendations."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt)
            ]

            response = await llm_client.chat_completion(
                messages=messages,
                temperature=0.2,
                max_tokens=800
            )

            try:
                return json.loads(response.content)
            except json.JSONDecodeError:
                return {
                    "summary": "AI analysis unavailable",
                    "confidence": 0.0
                }

        except Exception as e:
            logging.error(f"Error in AI evidence analysis: {e}")
            return {}

    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating file hash: {e}")
            return ""

    async def _analyze_file_signature(self, file_path: str) -> str:
        """Analyze file signature/magic bytes"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)

            # Simple signature detection
            signatures = {
                b"\x4D\x5A": "PE Executable",
                b"\x50\x4B": "ZIP Archive",
                b"\xFF\xD8": "JPEG Image",
                b"\x89\x50\x4E\x47": "PNG Image"
            }

            for sig, file_type in signatures.items():
                if header.startswith(sig):
                    return file_type

            return "Unknown"
        except Exception as e:
            logging.error(f"Error analyzing file signature: {e}")
            return "Error"

    async def _extract_strings(self, file_path: str) -> List[str]:
        """Extract interesting strings from file"""
        try:
            # Simulate string extraction
            interesting_strings = [
                "malicious.com",
                "C:\\temp\\evil.exe",
                "password123",
                "admin@company.com",
                "SELECT * FROM users"
            ]
            return interesting_strings
        except Exception as e:
            logging.error(f"Error extracting strings: {e}")
            return []

    async def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            # Simplified entropy calculation
            with open(file_path, "rb") as f:
                data = f.read(1024)  # Sample first 1KB

            if not data:
                return 0.0

            # Simple entropy approximation
            unique_bytes = len(set(data))
            max_entropy = 8.0  # Maximum entropy for byte data
            return (unique_bytes / 256.0) * max_entropy

        except Exception as e:
            logging.error(f"Error calculating entropy: {e}")
            return 0.0

    async def _yara_scan(self, file_path: str) -> List[str]:
        """Scan file with YARA rules"""
        try:
            # Simulate YARA scanning
            mock_matches = []

            # Simple pattern matching simulation
            with open(file_path, "rb") as f:
                content = f.read().lower()

            patterns = {
                b"malicious": "Generic_Malware",
                b"evil": "Suspicious_Behavior",
                b"backdoor": "Backdoor_Pattern"
            }

            for pattern, rule_name in patterns.items():
                if pattern in content:
                    mock_matches.append(rule_name)

            return mock_matches
        except Exception as e:
            logging.error(f"Error in YARA scanning: {e}")
            return []

    async def _setup_workspace(self):
        """Setup forensic workspace directories"""
        try:
            os.makedirs(self.workspace_path, exist_ok=True)
            os.makedirs(self.evidence_path, exist_ok=True)
            logging.info(f"Forensic workspace setup at {self.workspace_path}")
        except Exception as e:
            logging.error(f"Error setting up workspace: {e}")

    async def _initialize_forensic_tools(self):
        """Initialize available forensic tools"""
        self.forensic_tools = {
            "volatility": {"available": True, "version": "3.0"},
            "yara": {"available": True, "version": "4.2"},
            "sleuthkit": {"available": True, "version": "4.10"},
            "autopsy": {"available": False, "version": "N/A"},
            "strings": {"available": True, "version": "system"},
            "file": {"available": True, "version": "system"}
        }

    async def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        self.yara_rules = [
            "rule Generic_Malware { strings: $a = \"malicious\" condition: $a }",
            "rule Suspicious_Behavior { strings: $a = \"evil\" condition: $a }",
            "rule Backdoor_Pattern { strings: $a = \"backdoor\" condition: $a }"
        ]

    async def _update_case_timeline(self, case: ForensicCase, event: BaseEvent, evidence_items: List[ForensicEvidence]):
        """Update forensic case timeline"""
        try:
            timeline_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "evidence_collection",
                "description": f"Collected {len(evidence_items)} evidence items for {event.event_type}",
                "evidence_ids": [e.evidence_id for e in evidence_items],
                "trigger_event": event.event_id
            }
            case.timeline.append(timeline_entry)
        except Exception as e:
            logging.error(f"Error updating case timeline: {e}")

    async def _create_forensic_event(self, trigger_event: BaseEvent, case: ForensicCase, analysis_results: List[Dict[str, Any]]) -> BaseEvent:
        """Create forensic analysis event"""
        return BaseEvent(
            event_type="forensic_analysis_completed",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.DETECTION_FINDING,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"case_id": case.case_id, "incident_id": case.incident_id},
            message=f"Forensic analysis completed for case {case.case_id}",
            risk=60,
            confidence=0.8,
            enrichment={
                "forensic_case": {
                    "case_id": case.case_id,
                    "evidence_count": len(case.evidence_items),
                    "findings_count": sum(len(r.get("findings", [])) for r in analysis_results),
                    "techniques_used": list(set([t for r in analysis_results for t in r.get("techniques_used", [])]))
                },
                "trigger_event": {
                    "event_id": trigger_event.event_id,
                    "event_type": trigger_event.event_type
                }
            }
        )

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Archive active cases
            for case_id in list(self.active_cases.keys()):
                case = self.active_cases[case_id]
                case.status = "archived"
                logging.info(f"Archived forensic case {case_id} during shutdown")

            self.active_cases.clear()

            logging.info("Digital Forensics Analyzer cleanup completed")

        except Exception as e:
            logging.error(f"Error during Digital Forensics Analyzer cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get forensics analyzer metrics"""
        return {
            **super().get_metrics(),
            "active_cases": len(self.active_cases),
            "total_evidence": len(self.evidence_vault),
            "evidence_by_type": {
                etype.value: len([e for e in self.evidence_vault.values() if e.evidence_type == etype])
                for etype in EvidenceType
            },
            "cases_by_status": {
                status: len([c for c in self.active_cases.values() if c.status == status])
                for status in ["active", "closed", "archived"]
            },
            "forensic_tools": len(self.forensic_tools),
            "yara_rules_loaded": len(self.yara_rules)
        }


# Global instance
digital_forensics_analyzer = DigitalForensicsAnalyzer()