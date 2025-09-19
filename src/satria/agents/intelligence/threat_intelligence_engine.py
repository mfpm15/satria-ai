"""
SATRIA AI - Threat Intelligence Engine
Advanced threat intelligence integration with MISP, OpenCTI, and multiple feeds
"""

import asyncio
import logging
import aiohttp
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from urllib.parse import urlparse

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class ThreatType(str, Enum):
    """Types of threat indicators"""
    MALWARE_HASH = "malware_hash"
    MALICIOUS_IP = "malicious_ip"
    MALICIOUS_DOMAIN = "malicious_domain"
    MALICIOUS_URL = "malicious_url"
    BOTNET_C2 = "botnet_c2"
    PHISHING = "phishing"
    APT_INDICATOR = "apt_indicator"
    COMPROMISED_CREDENTIAL = "compromised_credential"
    YARA_RULE = "yara_rule"
    SIGMA_RULE = "sigma_rule"


class ThreatSource(str, Enum):
    """Threat intelligence sources"""
    MISP = "misp"
    OPENCTI = "opencti"
    VIRUSTOTAL = "virustotal"
    ALIENVAULT_OTX = "alienvault_otx"
    THREATFOX = "threatfox"
    URLVOID = "urlvoid"
    ABUSEIPDB = "abuseipdb"
    INTERNAL = "internal"


class ConfidenceLevel(str, Enum):
    """Confidence levels for threat indicators"""
    HIGH = "high"      # 80-100%
    MEDIUM = "medium"  # 50-79%
    LOW = "low"        # 20-49%
    UNKNOWN = "unknown" # 0-19%


@dataclass
class ThreatIndicator:
    """Threat intelligence indicator"""
    indicator: str
    indicator_type: ThreatType
    threat_score: int  # 0-100
    confidence: ConfidenceLevel
    source: ThreatSource
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    apt_groups: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expiration_date: Optional[datetime] = None
    is_active: bool = True


@dataclass
class ThreatCampaign:
    """Threat campaign information"""
    campaign_id: str
    name: str
    description: str
    threat_actors: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    is_active: bool = True


@dataclass
class ThreatEnrichment:
    """Threat enrichment results"""
    indicator: str
    matches: List[ThreatIndicator] = field(default_factory=list)
    overall_threat_score: int = 0
    max_confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    sources: Set[str] = field(default_factory=set)
    enrichment_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatIntelligenceEngine(BaseAgent):
    """
    Advanced Threat Intelligence Engine
    Integrates with multiple threat intel sources for comprehensive enrichment
    """

    def __init__(self):
        super().__init__(
            name="threat_intelligence_engine",
            description="Advanced threat intelligence integration and enrichment",
            version="2.0.0"
        )

        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.threat_campaigns: Dict[str, ThreatCampaign] = {}
        self.session: Optional[aiohttp.ClientSession] = None

        # Statistics
        self.enrichment_requests = 0
        self.hits = 0
        self.misses = 0
        self.api_errors = 0

        # Cache settings
        self.cache_duration = timedelta(hours=6)
        self.enrichment_cache: Dict[str, ThreatEnrichment] = {}

        # Feed update intervals
        self.feed_update_intervals = {
            ThreatSource.MISP: timedelta(minutes=15),
            ThreatSource.OPENCTI: timedelta(minutes=30),
            ThreatSource.VIRUSTOTAL: timedelta(hours=1),
            ThreatSource.ALIENVAULT_OTX: timedelta(hours=2),
            ThreatSource.THREATFOX: timedelta(hours=1),
            ThreatSource.ABUSEIPDB: timedelta(hours=6)
        }

    async def initialize(self) -> bool:
        """Initialize threat intelligence engine"""
        try:
            # Initialize HTTP session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "SATRIA-AI-ThreatIntel/2.0"}
            )

            # Load existing threat indicators
            await self._load_threat_indicators()

            # Initialize threat intel sources
            await self._initialize_threat_sources()

            # Start periodic tasks
            asyncio.create_task(self._periodic_feed_updates())
            asyncio.create_task(self._periodic_cache_cleanup())
            asyncio.create_task(self._periodic_indicator_validation())

            logging.info("Threat Intelligence Engine initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Threat Intelligence Engine: {e}")
            return False

    async def _initialize_threat_sources(self):
        """Initialize connections to threat intelligence sources"""
        sources_initialized = []

        # MISP initialization
        if settings.misp_url and settings.misp_api_key:
            if await self._test_misp_connection():
                sources_initialized.append(ThreatSource.MISP)
                asyncio.create_task(self._sync_misp_indicators())

        # OpenCTI initialization
        if settings.opencti_url and settings.opencti_token:
            if await self._test_opencti_connection():
                sources_initialized.append(ThreatSource.OPENCTI)
                asyncio.create_task(self._sync_opencti_indicators())

        # Initialize open source feeds
        sources_initialized.extend([
            ThreatSource.THREATFOX,
            ThreatSource.ABUSEIPDB,
            ThreatSource.URLVOID
        ])

        logging.info(f"Initialized threat intelligence sources: {sources_initialized}")

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for threat intelligence enrichment"""
        try:
            # Extract indicators from event
            indicators = self._extract_indicators_from_event(event)
            if not indicators:
                return [event]

            # Enrich each indicator
            enrichments = []
            for indicator_type, indicator_value in indicators:
                enrichment = await self._enrich_indicator(indicator_value, indicator_type)
                if enrichment.matches:
                    enrichments.append(enrichment)

            # Apply enrichment to event
            if enrichments:
                await self._apply_threat_enrichment(event, enrichments)

            return [event]

        except Exception as e:
            logging.error(f"Error in threat intelligence processing: {e}")
            return [event]

    def _extract_indicators_from_event(self, event: BaseEvent) -> List[Tuple[ThreatType, str]]:
        """Extract threat indicators from event"""
        indicators = []

        try:
            # Extract IP addresses
            for ip_field in ["source_ip", "dest_ip", "client_ip"]:
                ip = event.entity_ids.get(ip_field) or event.enrichment.get(ip_field)
                if ip and self._is_valid_ip(ip):
                    indicators.append((ThreatType.MALICIOUS_IP, ip))

            # Extract domains
            domain = event.enrichment.get("domain")
            if domain and self._is_valid_domain(domain):
                indicators.append((ThreatType.MALICIOUS_DOMAIN, domain))

            # Extract URLs
            url = event.enrichment.get("url")
            if url and self._is_valid_url(url):
                indicators.append((ThreatType.MALICIOUS_URL, url))

            # Extract file hashes
            for hash_field in ["file_hash", "md5", "sha1", "sha256"]:
                hash_value = event.enrichment.get(hash_field)
                if hash_value and self._is_valid_hash(hash_value):
                    indicators.append((ThreatType.MALWARE_HASH, hash_value))

            # Extract from raw log data
            raw_log = event.enrichment.get("raw_log", "")
            if raw_log:
                indicators.extend(self._extract_indicators_from_text(raw_log))

            return indicators

        except Exception as e:
            logging.error(f"Error extracting indicators: {e}")
            return []

    async def _enrich_indicator(self, indicator: str, indicator_type: ThreatType) -> ThreatEnrichment:
        """Enrich a single indicator"""
        self.enrichment_requests += 1

        # Check cache first
        cache_key = f"{indicator_type.value}:{indicator}"
        if cache_key in self.enrichment_cache:
            cached = self.enrichment_cache[cache_key]
            if datetime.now(timezone.utc) - cached.enrichment_timestamp < self.cache_duration:
                return cached

        enrichment = ThreatEnrichment(indicator=indicator)

        try:
            # Check local indicators first
            local_matches = self._search_local_indicators(indicator, indicator_type)
            enrichment.matches.extend(local_matches)

            # Query external sources based on indicator type
            if indicator_type == ThreatType.MALICIOUS_IP:
                await self._enrich_ip_indicator(indicator, enrichment)
            elif indicator_type == ThreatType.MALICIOUS_DOMAIN:
                await self._enrich_domain_indicator(indicator, enrichment)
            elif indicator_type == ThreatType.MALICIOUS_URL:
                await self._enrich_url_indicator(indicator, enrichment)
            elif indicator_type == ThreatType.MALWARE_HASH:
                await self._enrich_hash_indicator(indicator, enrichment)

            # Calculate overall threat score
            if enrichment.matches:
                enrichment.overall_threat_score = max(match.threat_score for match in enrichment.matches)
                enrichment.max_confidence = max(
                    [match.confidence for match in enrichment.matches],
                    key=lambda x: ["unknown", "low", "medium", "high"].index(x.value)
                )
                enrichment.sources = set(match.source.value for match in enrichment.matches)
                self.hits += 1
            else:
                self.misses += 1

            # Cache result
            self.enrichment_cache[cache_key] = enrichment

            return enrichment

        except Exception as e:
            logging.error(f"Error enriching indicator {indicator}: {e}")
            self.api_errors += 1
            return enrichment

    def _search_local_indicators(self, indicator: str, indicator_type: ThreatType) -> List[ThreatIndicator]:
        """Search local threat indicators"""
        matches = []

        for threat_indicator in self.threat_indicators.values():
            if not threat_indicator.is_active:
                continue

            if threat_indicator.indicator_type == indicator_type:
                if threat_indicator.indicator == indicator:
                    matches.append(threat_indicator)
                elif indicator_type == ThreatType.MALICIOUS_IP:
                    # Check for subnet matches
                    if self._ip_in_cidr(indicator, threat_indicator.indicator):
                        matches.append(threat_indicator)

        return matches

    async def _enrich_ip_indicator(self, ip: str, enrichment: ThreatEnrichment):
        """Enrich IP indicator from multiple sources"""
        try:
            # AbuseIPDB
            await self._query_abuseipdb(ip, enrichment)

            # AlienVault OTX
            await self._query_otx_ip(ip, enrichment)

            # Internal blacklists
            await self._check_internal_ip_blacklist(ip, enrichment)

        except Exception as e:
            logging.error(f"Error enriching IP {ip}: {e}")

    async def _enrich_domain_indicator(self, domain: str, enrichment: ThreatEnrichment):
        """Enrich domain indicator"""
        try:
            # URLVoid
            await self._query_urlvoid_domain(domain, enrichment)

            # AlienVault OTX
            await self._query_otx_domain(domain, enrichment)

            # Check domain reputation
            await self._check_domain_reputation(domain, enrichment)

        except Exception as e:
            logging.error(f"Error enriching domain {domain}: {e}")

    async def _enrich_hash_indicator(self, file_hash: str, enrichment: ThreatEnrichment):
        """Enrich file hash indicator"""
        try:
            # VirusTotal (if available)
            if hasattr(settings, 'virustotal_api_key'):
                await self._query_virustotal_hash(file_hash, enrichment)

            # ThreatFox
            await self._query_threatfox_hash(file_hash, enrichment)

            # Internal malware database
            await self._check_internal_hash_database(file_hash, enrichment)

        except Exception as e:
            logging.error(f"Error enriching hash {file_hash}: {e}")

    async def _query_abuseipdb(self, ip: str, enrichment: ThreatEnrichment):
        """Query AbuseIPDB for IP reputation"""
        try:
            # Mock implementation - in production would use real AbuseIPDB API
            if self._is_suspicious_ip(ip):
                threat_indicator = ThreatIndicator(
                    indicator=ip,
                    indicator_type=ThreatType.MALICIOUS_IP,
                    threat_score=75,
                    confidence=ConfidenceLevel.HIGH,
                    source=ThreatSource.ABUSEIPDB,
                    first_seen=datetime.now(timezone.utc) - timedelta(days=30),
                    last_seen=datetime.now(timezone.utc),
                    description="Reported for malicious activity",
                    tags=["scanning", "brute_force"],
                    metadata={"abuse_confidence": 85, "country": "CN", "usage_type": "datacenter"}
                )
                enrichment.matches.append(threat_indicator)

        except Exception as e:
            logging.error(f"Error querying AbuseIPDB: {e}")

    async def _query_threatfox_hash(self, file_hash: str, enrichment: ThreatEnrichment):
        """Query ThreatFox for hash reputation"""
        try:
            # Mock implementation
            if len(file_hash) == 32 and file_hash.startswith('a'):  # Mock condition
                threat_indicator = ThreatIndicator(
                    indicator=file_hash,
                    indicator_type=ThreatType.MALWARE_HASH,
                    threat_score=90,
                    confidence=ConfidenceLevel.HIGH,
                    source=ThreatSource.THREATFOX,
                    first_seen=datetime.now(timezone.utc) - timedelta(days=7),
                    last_seen=datetime.now(timezone.utc),
                    description="Known malware sample",
                    malware_families=["emotet", "trickbot"],
                    tags=["banking_trojan", "credential_theft"],
                    mitre_techniques=["T1055", "T1027"]
                )
                enrichment.matches.append(threat_indicator)

        except Exception as e:
            logging.error(f"Error querying ThreatFox: {e}")

    async def _apply_threat_enrichment(self, event: BaseEvent, enrichments: List[ThreatEnrichment]):
        """Apply threat intelligence enrichment to event"""
        try:
            # Calculate overall threat intelligence score
            max_threat_score = max(e.overall_threat_score for e in enrichments)

            # Increase event risk based on threat intelligence
            if max_threat_score > 0:
                threat_intelligence_boost = min(30, max_threat_score * 0.3)
                event.risk = min(100, event.risk + int(threat_intelligence_boost))

            # Add threat intelligence data to enrichment
            if "threat_intelligence" not in event.enrichment:
                event.enrichment["threat_intelligence"] = {}

            threat_intel_data = {
                "matches_found": len(enrichments),
                "max_threat_score": max_threat_score,
                "sources": list(set().union(*[e.sources for e in enrichments])),
                "indicators": []
            }

            for enrichment in enrichments:
                for match in enrichment.matches:
                    indicator_data = {
                        "indicator": match.indicator,
                        "type": match.indicator_type.value,
                        "threat_score": match.threat_score,
                        "confidence": match.confidence.value,
                        "source": match.source.value,
                        "description": match.description,
                        "tags": match.tags,
                        "malware_families": match.malware_families,
                        "apt_groups": match.apt_groups,
                        "mitre_techniques": match.mitre_techniques
                    }
                    threat_intel_data["indicators"].append(indicator_data)

            event.enrichment["threat_intelligence"] = threat_intel_data

            # Create threat intelligence event if high-confidence matches
            if max_threat_score >= 70:
                await self._create_threat_intel_event(event, enrichments)

            logging.info(f"Applied threat intelligence enrichment: {len(enrichments)} indicators, max score: {max_threat_score}")

        except Exception as e:
            logging.error(f"Error applying threat enrichment: {e}")

    async def _create_threat_intel_event(self, original_event: BaseEvent, enrichments: List[ThreatEnrichment]):
        """Create dedicated threat intelligence event"""
        try:
            max_threat_score = max(e.overall_threat_score for e in enrichments)
            all_sources = set().union(*[e.sources for e in enrichments])

            threat_event = BaseEvent(
                event_type="threat_intelligence_match",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                entity_ids=original_event.entity_ids.copy(),
                message=f"Threat intelligence matches found: {len(enrichments)} indicators",
                risk=max_threat_score,
                confidence=0.9,
                enrichment={
                    "original_event_id": original_event.event_id,
                    "threat_matches": len(enrichments),
                    "threat_sources": list(all_sources),
                    "max_threat_score": max_threat_score,
                    "matched_indicators": [
                        {
                            "indicator": e.indicator,
                            "matches": len(e.matches)
                        } for e in enrichments
                    ]
                }
            )

            await event_bus.publish(threat_event)

        except Exception as e:
            logging.error(f"Error creating threat intel event: {e}")

    async def _sync_misp_indicators(self):
        """Sync indicators from MISP"""
        try:
            if not settings.misp_url or not settings.misp_api_key:
                return

            # Mock MISP sync - in production would use pymisp
            mock_indicators = [
                {
                    "value": "185.220.101.182",
                    "type": "ip-dst",
                    "category": "Network activity",
                    "threat_level": "High",
                    "tags": ["tor", "exit_node"],
                    "first_seen": datetime.now(timezone.utc) - timedelta(days=30),
                    "last_seen": datetime.now(timezone.utc)
                }
            ]

            for indicator_data in mock_indicators:
                threat_indicator = ThreatIndicator(
                    indicator=indicator_data["value"],
                    indicator_type=ThreatType.MALICIOUS_IP,
                    threat_score=80,
                    confidence=ConfidenceLevel.HIGH,
                    source=ThreatSource.MISP,
                    first_seen=indicator_data["first_seen"],
                    last_seen=indicator_data["last_seen"],
                    description=f"MISP indicator: {indicator_data['category']}",
                    tags=indicator_data["tags"]
                )

                self.threat_indicators[f"misp:{indicator_data['value']}"] = threat_indicator

            logging.info(f"Synced {len(mock_indicators)} indicators from MISP")

        except Exception as e:
            logging.error(f"Error syncing MISP indicators: {e}")

    # Validation helper methods
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(domain))

    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash format"""
        hash_patterns = {
            32: r'^[a-fA-F0-9]{32}$',  # MD5
            40: r'^[a-fA-F0-9]{40}$',  # SHA1
            64: r'^[a-fA-F0-9]{64}$'   # SHA256
        }
        return any(re.match(pattern, hash_value) for pattern in hash_patterns.values())

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Close HTTP sessions
            if hasattr(self, 'session') and self.session:
                await self.session.close()

            # Clear cached enrichments
            self.cached_enrichments.clear()

            # Clear indicator cache
            if hasattr(self, 'indicator_cache'):
                self.indicator_cache.clear()

            self.logger.info("Threat intelligence engine cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get threat intelligence metrics"""
        return {
            **super().get_metrics(),
            "enrichment_requests": self.enrichment_requests,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / max(1, self.enrichment_requests),
            "api_errors": self.api_errors,
            "cached_enrichments": len(self.enrichment_cache),
            "threat_indicators": len(self.threat_indicators),
            "threat_campaigns": len(self.threat_campaigns)
        }


# Global instance
threat_intelligence_engine = ThreatIntelligenceEngine()