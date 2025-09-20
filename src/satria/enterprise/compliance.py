"""
SATRIA AI Enterprise Compliance Engine
Comprehensive regulatory compliance mapping and monitoring
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class RegulationType(str, Enum):
    """Supported regulatory frameworks"""
    GDPR = "gdpr"                    # General Data Protection Regulation
    SOX = "sox"                      # Sarbanes-Oxley Act
    PCI_DSS = "pci_dss"             # Payment Card Industry Data Security Standard
    HIPAA = "hipaa"                  # Health Insurance Portability and Accountability Act
    NIST_CSF = "nist_csf"           # NIST Cybersecurity Framework
    ISO_27001 = "iso_27001"         # ISO/IEC 27001
    SOC_2 = "soc_2"                 # SOC 2 Type II
    CCPA = "ccpa"                   # California Consumer Privacy Act
    FISMA = "fisma"                 # Federal Information Security Management Act
    COBIT = "cobit"                 # Control Objectives for Information Technologies


class ComplianceStatus(str, Enum):
    """Compliance status indicators"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    UNDER_REVIEW = "under_review"
    NOT_APPLICABLE = "not_applicable"


class ControlCategory(str, Enum):
    """Security control categories"""
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    INCIDENT_RESPONSE = "incident_response"
    MONITORING = "monitoring"
    AUDIT_LOGGING = "audit_logging"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    BUSINESS_CONTINUITY = "business_continuity"
    RISK_MANAGEMENT = "risk_management"
    VENDOR_MANAGEMENT = "vendor_management"
    TRAINING = "training"


@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    requirement_id: str
    regulation: RegulationType
    section: str
    title: str
    description: str
    control_objective: str
    implementation_guidance: str
    evidence_required: List[str] = field(default_factory=list)
    frequency: str = "annual"  # daily, weekly, monthly, quarterly, annual
    category: ControlCategory = ControlCategory.MONITORING
    criticality: str = "medium"  # low, medium, high, critical
    automated: bool = False
    responsible_party: str = "security_team"


@dataclass
class ComplianceControl:
    """Security control implementation"""
    control_id: str
    name: str
    description: str
    category: ControlCategory
    implementation_status: ComplianceStatus
    requirements: List[str] = field(default_factory=list)  # Requirement IDs
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    test_procedures: List[str] = field(default_factory=list)
    last_tested: Optional[datetime] = None
    next_review: Optional[datetime] = None
    risk_rating: str = "medium"
    compensating_controls: List[str] = field(default_factory=list)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceGap:
    """Identified compliance gap"""
    gap_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation: RegulationType
    requirement_id: str
    description: str
    risk_level: str = "medium"
    impact: str = ""
    remediation_plan: str = ""
    target_date: Optional[datetime] = None
    responsible_party: str = ""
    status: str = "identified"  # identified, in_progress, remediated
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComplianceAssessment:
    """Compliance assessment results"""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation: RegulationType
    assessment_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scope: str = "full"
    overall_score: float = 0.0
    requirements_total: int = 0
    requirements_compliant: int = 0
    requirements_partial: int = 0
    requirements_non_compliant: int = 0
    gaps: List[ComplianceGap] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    next_assessment: Optional[datetime] = None
    assessor: str = "satria_ai"


class ComplianceEngine(BaseAgent):
    """
    Enterprise Compliance Engine
    Comprehensive regulatory compliance mapping and monitoring
    """

    def __init__(self):
        super().__init__(
            name="compliance_engine",
            description="Enterprise regulatory compliance management",
            version="4.0.0"
        )

        self.regulations: Dict[RegulationType, Dict[str, Any]] = {}
        self.requirements: Dict[str, ComplianceRequirement] = {}
        self.controls: Dict[str, ComplianceControl] = {}
        self.assessments: Dict[str, ComplianceAssessment] = {}
        self.gaps: Dict[str, ComplianceGap] = {}

        # Compliance monitoring
        self.monitoring_rules: Dict[str, Dict[str, Any]] = {}
        self.breach_notifications: List[Dict[str, Any]] = []

    async def initialize(self) -> bool:
        """Initialize compliance engine"""
        try:
            # Load regulatory frameworks
            await self._load_regulatory_frameworks()

            # Load compliance requirements
            await self._load_compliance_requirements()

            # Initialize security controls
            await self._initialize_security_controls()

            # Setup monitoring rules
            await self._setup_compliance_monitoring()

            logging.info("Compliance Engine initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Compliance Engine: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for compliance monitoring"""
        try:
            compliance_events = []

            # Check for compliance violations
            violations = await self._check_compliance_violations(event)

            # Check for data breach indicators
            breach_indicators = await self._check_breach_indicators(event)

            # Update compliance metrics
            await self._update_compliance_metrics(event)

            # Generate compliance events if needed
            if violations:
                for violation in violations:
                    compliance_event = await self._create_compliance_violation_event(event, violation)
                    compliance_events.append(compliance_event)

            if breach_indicators:
                breach_event = await self._create_breach_notification_event(event, breach_indicators)
                compliance_events.append(breach_event)

            return [event] + compliance_events

        except Exception as e:
            logging.error(f"Error processing event for compliance: {e}")
            return [event]

    async def conduct_compliance_assessment(self, regulation: RegulationType, scope: str = "full") -> ComplianceAssessment:
        """Conduct comprehensive compliance assessment"""
        try:
            assessment = ComplianceAssessment(
                regulation=regulation,
                scope=scope
            )

            # Get requirements for regulation
            regulation_requirements = [
                req for req in self.requirements.values()
                if req.regulation == regulation
            ]

            assessment.requirements_total = len(regulation_requirements)

            # Assess each requirement
            for requirement in regulation_requirements:
                status = await self._assess_requirement(requirement)

                if status == ComplianceStatus.COMPLIANT:
                    assessment.requirements_compliant += 1
                elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
                    assessment.requirements_partial += 1
                elif status == ComplianceStatus.NON_COMPLIANT:
                    assessment.requirements_non_compliant += 1

                    # Create gap for non-compliant requirements
                    gap = ComplianceGap(
                        regulation=regulation,
                        requirement_id=requirement.requirement_id,
                        description=f"Non-compliance with {requirement.title}",
                        risk_level=requirement.criticality,
                        impact=f"Potential regulatory violation: {requirement.control_objective}"
                    )
                    assessment.gaps.append(gap)
                    self.gaps[gap.gap_id] = gap

            # Calculate overall score
            if assessment.requirements_total > 0:
                assessment.overall_score = (
                    (assessment.requirements_compliant + 0.5 * assessment.requirements_partial)
                    / assessment.requirements_total
                ) * 100

            # Generate recommendations
            assessment.recommendations = await self._generate_compliance_recommendations(assessment)

            # Set next assessment date
            assessment.next_assessment = datetime.now(timezone.utc) + timedelta(days=365)

            # Store assessment
            self.assessments[assessment.assessment_id] = assessment

            logging.info(f"Compliance assessment completed for {regulation.value}: {assessment.overall_score:.1f}%")

            return assessment

        except Exception as e:
            logging.error(f"Error conducting compliance assessment: {e}")
            raise

    async def _load_regulatory_frameworks(self):
        """Load regulatory framework definitions"""
        self.regulations = {
            RegulationType.GDPR: {
                "name": "General Data Protection Regulation",
                "jurisdiction": "European Union",
                "effective_date": "2018-05-25",
                "scope": "Data protection and privacy",
                "key_requirements": [
                    "Data protection by design",
                    "Breach notification (72 hours)",
                    "Data subject rights",
                    "Privacy impact assessments",
                    "Data protection officer"
                ],
                "penalties": "Up to 4% of annual revenue or €20M"
            },

            RegulationType.SOX: {
                "name": "Sarbanes-Oxley Act",
                "jurisdiction": "United States",
                "effective_date": "2002-07-30",
                "scope": "Financial reporting and corporate governance",
                "key_requirements": [
                    "Internal controls over financial reporting",
                    "Management assessment",
                    "Auditor attestation",
                    "IT general controls",
                    "Change management"
                ],
                "penalties": "Criminal and civil penalties"
            },

            RegulationType.PCI_DSS: {
                "name": "Payment Card Industry Data Security Standard",
                "jurisdiction": "Global",
                "effective_date": "2004-12-15",
                "scope": "Cardholder data protection",
                "key_requirements": [
                    "Build and maintain secure network",
                    "Protect cardholder data",
                    "Maintain vulnerability management",
                    "Implement access controls",
                    "Monitor and test networks",
                    "Maintain information security policy"
                ],
                "penalties": "Fines and loss of processing privileges"
            },

            RegulationType.HIPAA: {
                "name": "Health Insurance Portability and Accountability Act",
                "jurisdiction": "United States",
                "effective_date": "1996-08-21",
                "scope": "Protected health information",
                "key_requirements": [
                    "Administrative safeguards",
                    "Physical safeguards",
                    "Technical safeguards",
                    "Business associate agreements",
                    "Breach notification"
                ],
                "penalties": "Up to $1.5M per incident"
            },

            RegulationType.NIST_CSF: {
                "name": "NIST Cybersecurity Framework",
                "jurisdiction": "United States",
                "effective_date": "2014-02-12",
                "scope": "Cybersecurity risk management",
                "key_requirements": [
                    "Identify assets and risks",
                    "Protect critical assets",
                    "Detect cybersecurity events",
                    "Respond to incidents",
                    "Recover from incidents"
                ],
                "penalties": "Voluntary framework"
            },

            RegulationType.ISO_27001: {
                "name": "ISO/IEC 27001",
                "jurisdiction": "International",
                "effective_date": "2005-10-15",
                "scope": "Information security management",
                "key_requirements": [
                    "Information security management system",
                    "Risk assessment and treatment",
                    "Statement of applicability",
                    "Management review",
                    "Continuous improvement"
                ],
                "penalties": "Loss of certification"
            }
        }

    async def _load_compliance_requirements(self):
        """Load detailed compliance requirements"""

        # GDPR Requirements
        gdpr_requirements = [
            ComplianceRequirement(
                requirement_id="GDPR-Art25",
                regulation=RegulationType.GDPR,
                section="Article 25",
                title="Data protection by design and by default",
                description="Implement appropriate technical and organisational measures to ensure data protection",
                control_objective="Ensure data protection is built into systems and processes",
                implementation_guidance="Implement privacy-enhancing technologies and data minimization",
                evidence_required=["system_design_docs", "privacy_impact_assessments", "data_flow_diagrams"],
                frequency="ongoing",
                category=ControlCategory.DATA_PROTECTION,
                criticality="high",
                automated=True
            ),

            ComplianceRequirement(
                requirement_id="GDPR-Art33",
                regulation=RegulationType.GDPR,
                section="Article 33",
                title="Notification of personal data breach to supervisory authority",
                description="Notify supervisory authority of data breaches within 72 hours",
                control_objective="Ensure timely breach notification to authorities",
                implementation_guidance="Automated breach detection and notification system",
                evidence_required=["breach_notification_logs", "incident_response_procedures"],
                frequency="as_needed",
                category=ControlCategory.INCIDENT_RESPONSE,
                criticality="critical",
                automated=True
            ),

            ComplianceRequirement(
                requirement_id="GDPR-Art34",
                regulation=RegulationType.GDPR,
                section="Article 34",
                title="Communication of personal data breach to data subject",
                description="Notify data subjects of high-risk breaches without undue delay",
                control_objective="Inform affected individuals of data breaches",
                implementation_guidance="Automated data subject notification system",
                evidence_required=["data_subject_notifications", "communication_templates"],
                frequency="as_needed",
                category=ControlCategory.INCIDENT_RESPONSE,
                criticality="high",
                automated=True
            )
        ]

        # SOX Requirements
        sox_requirements = [
            ComplianceRequirement(
                requirement_id="SOX-302",
                regulation=RegulationType.SOX,
                section="Section 302",
                title="Corporate responsibility for financial reports",
                description="CEOs and CFOs must certify financial reports",
                control_objective="Ensure executive accountability for financial reporting",
                implementation_guidance="Implement certification process and controls",
                evidence_required=["certification_documents", "control_documentation"],
                frequency="quarterly",
                category=ControlCategory.AUDIT_LOGGING,
                criticality="critical",
                automated=False
            ),

            ComplianceRequirement(
                requirement_id="SOX-404",
                regulation=RegulationType.SOX,
                section="Section 404",
                title="Management assessment of internal controls",
                description="Assess internal controls over financial reporting",
                control_objective="Ensure effective internal controls",
                implementation_guidance="Regular testing and documentation of controls",
                evidence_required=["control_testing_results", "management_assessment"],
                frequency="annual",
                category=ControlCategory.AUDIT_LOGGING,
                criticality="high",
                automated=True
            )
        ]

        # PCI DSS Requirements
        pci_requirements = [
            ComplianceRequirement(
                requirement_id="PCI-DSS-1",
                regulation=RegulationType.PCI_DSS,
                section="Requirement 1",
                title="Install and maintain firewall configuration",
                description="Protect cardholder data with firewall controls",
                control_objective="Control network access to cardholder data",
                implementation_guidance="Implement and maintain firewall rules",
                evidence_required=["firewall_configurations", "rule_reviews"],
                frequency="quarterly",
                category=ControlCategory.ACCESS_CONTROL,
                criticality="high",
                automated=True
            ),

            ComplianceRequirement(
                requirement_id="PCI-DSS-10",
                regulation=RegulationType.PCI_DSS,
                section="Requirement 10",
                title="Track and monitor access to network resources",
                description="Log and monitor all access to cardholder data",
                control_objective="Ensure comprehensive audit logging",
                implementation_guidance="Implement centralized logging and monitoring",
                evidence_required=["audit_logs", "monitoring_reports"],
                frequency="continuous",
                category=ControlCategory.AUDIT_LOGGING,
                criticality="high",
                automated=True
            )
        ]

        # Store all requirements
        for req_list in [gdpr_requirements, sox_requirements, pci_requirements]:
            for req in req_list:
                self.requirements[req.requirement_id] = req

    async def _initialize_security_controls(self):
        """Initialize security control mappings"""
        controls = [
            ComplianceControl(
                control_id="AC-001",
                name="Multi-Factor Authentication",
                description="Implement MFA for all user accounts",
                category=ControlCategory.ACCESS_CONTROL,
                implementation_status=ComplianceStatus.COMPLIANT,
                requirements=["PCI-DSS-8", "SOX-404", "GDPR-Art32"],
                test_procedures=["MFA_enabled_check", "bypass_attempt_test"],
                risk_rating="high"
            ),

            ComplianceControl(
                control_id="DP-001",
                name="Data Encryption at Rest",
                description="Encrypt sensitive data stored in databases",
                category=ControlCategory.DATA_PROTECTION,
                implementation_status=ComplianceStatus.COMPLIANT,
                requirements=["PCI-DSS-3", "GDPR-Art32", "HIPAA-164.312"],
                test_procedures=["encryption_verification", "key_management_review"],
                risk_rating="critical"
            ),

            ComplianceControl(
                control_id="IR-001",
                name="Automated Breach Notification",
                description="Automated system for breach detection and notification",
                category=ControlCategory.INCIDENT_RESPONSE,
                implementation_status=ComplianceStatus.COMPLIANT,
                requirements=["GDPR-Art33", "GDPR-Art34", "HIPAA-164.408"],
                test_procedures=["notification_timing_test", "template_review"],
                risk_rating="critical"
            ),

            ComplianceControl(
                control_id="AL-001",
                name="Comprehensive Audit Logging",
                description="Log all security-relevant events with immutable storage",
                category=ControlCategory.AUDIT_LOGGING,
                implementation_status=ComplianceStatus.COMPLIANT,
                requirements=["PCI-DSS-10", "SOX-404", "HIPAA-164.312"],
                test_procedures=["log_completeness_check", "immutability_test"],
                risk_rating="high"
            )
        ]

        for control in controls:
            self.controls[control.control_id] = control

    async def _setup_compliance_monitoring(self):
        """Setup automated compliance monitoring rules"""
        self.monitoring_rules = {
            "gdpr_breach_detection": {
                "regulation": RegulationType.GDPR,
                "requirement": "GDPR-Art33",
                "trigger_events": ["data_breach", "unauthorized_access", "data_exfiltration"],
                "notification_window": 72,  # hours
                "automated": True
            },

            "pci_cardholder_access": {
                "regulation": RegulationType.PCI_DSS,
                "requirement": "PCI-DSS-10",
                "trigger_events": ["cardholder_data_access", "payment_processing"],
                "monitoring": "continuous",
                "automated": True
            },

            "sox_financial_changes": {
                "regulation": RegulationType.SOX,
                "requirement": "SOX-404",
                "trigger_events": ["financial_system_access", "report_generation"],
                "approval_required": True,
                "automated": True
            }
        }

    async def _check_compliance_violations(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Check event for compliance violations"""
        violations = []

        try:
            # Check against monitoring rules
            for rule_id, rule in self.monitoring_rules.items():
                if event.event_type in rule.get("trigger_events", []):
                    violation = await self._assess_violation(event, rule)
                    if violation:
                        violations.append(violation)

            # Check for specific compliance patterns
            if event.event_type == "unauthorized_access":
                entity_ids = event.enrichment.get("entity_ids", {})
                if "financial_system" in entity_ids.get("system", ""):
                    violations.append({
                        "regulation": RegulationType.SOX,
                        "requirement": "SOX-404",
                        "violation_type": "unauthorized_financial_access",
                        "severity": "high",
                        "description": "Unauthorized access to financial systems"
                    })

            if event.event_type == "data_exfiltration":
                violations.append({
                    "regulation": RegulationType.GDPR,
                    "requirement": "GDPR-Art33",
                    "violation_type": "potential_data_breach",
                    "severity": "critical",
                    "description": "Potential GDPR data breach detected"
                })

        except Exception as e:
            logging.error(f"Error checking compliance violations: {e}")

        return violations

    async def _check_breach_indicators(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Check for data breach indicators requiring notification"""
        indicators = []

        try:
            # GDPR breach indicators
            gdpr_indicators = [
                "data_exfiltration",
                "unauthorized_access",
                "ransomware",
                "database_compromise"
            ]

            if event.event_type in gdpr_indicators:
                indicators.append({
                    "regulation": RegulationType.GDPR,
                    "breach_type": "personal_data_breach",
                    "notification_required": True,
                    "timeline": "72_hours",
                    "authorities": ["supervisory_authority"],
                    "data_subjects": True if (event.risk_score or 0) > 70 else False
                })

            # HIPAA breach indicators
            hipaa_indicators = [
                "phi_access",
                "medical_data_breach",
                "healthcare_system_compromise"
            ]

            if event.event_type in hipaa_indicators:
                indicators.append({
                    "regulation": RegulationType.HIPAA,
                    "breach_type": "phi_breach",
                    "notification_required": True,
                    "timeline": "60_days",
                    "authorities": ["hhs_ocr"],
                    "patients": True
                })

        except Exception as e:
            logging.error(f"Error checking breach indicators: {e}")

        return indicators

    async def _assess_violation(self, event: BaseEvent, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Assess if event constitutes a compliance violation"""
        try:
            # Simple rule-based assessment
            if event.event_type in rule.get("trigger_events", []):
                risk_score = event.risk_score or 0

                if risk_score > 70:  # High risk threshold
                    return {
                        "regulation": rule["regulation"],
                        "requirement": rule["requirement"],
                        "violation_type": f"{event.event_type}_violation",
                        "severity": "high" if risk_score > 85 else "medium",
                        "description": f"Compliance violation detected: {event.event_type}",
                        "event_id": event.event_id
                    }

            return None

        except Exception as e:
            logging.error(f"Error assessing violation: {e}")
            return None

    async def _assess_requirement(self, requirement: ComplianceRequirement) -> ComplianceStatus:
        """Assess compliance status of individual requirement"""
        try:
            # Find relevant controls for this requirement
            relevant_controls = [
                control for control in self.controls.values()
                if requirement.requirement_id in control.requirements
            ]

            if not relevant_controls:
                return ComplianceStatus.NON_COMPLIANT

            # Check control status
            compliant_controls = [
                control for control in relevant_controls
                if control.implementation_status == ComplianceStatus.COMPLIANT
            ]

            if len(compliant_controls) == len(relevant_controls):
                return ComplianceStatus.COMPLIANT
            elif len(compliant_controls) > 0:
                return ComplianceStatus.PARTIALLY_COMPLIANT
            else:
                return ComplianceStatus.NON_COMPLIANT

        except Exception as e:
            logging.error(f"Error assessing requirement: {e}")
            return ComplianceStatus.UNDER_REVIEW

    async def _generate_compliance_recommendations(self, assessment: ComplianceAssessment) -> List[str]:
        """Generate compliance improvement recommendations"""
        recommendations = []

        try:
            # High-level recommendations based on score
            if assessment.overall_score < 60:
                recommendations.append("Immediate compliance remediation required - consider engaging compliance consultant")
                recommendations.append("Implement comprehensive compliance program with dedicated resources")

            elif assessment.overall_score < 80:
                recommendations.append("Focus on addressing high-risk compliance gaps")
                recommendations.append("Enhance monitoring and detection capabilities")

            elif assessment.overall_score < 95:
                recommendations.append("Fine-tune existing controls for optimal compliance")
                recommendations.append("Implement continuous compliance monitoring")

            # Specific recommendations based on gaps
            for gap in assessment.gaps:
                if gap.risk_level == "critical":
                    recommendations.append(f"URGENT: Address {gap.description} immediately")
                elif gap.risk_level == "high":
                    recommendations.append(f"HIGH PRIORITY: Remediate {gap.description} within 30 days")

            # Regulation-specific recommendations
            if assessment.regulation == RegulationType.GDPR:
                recommendations.append("Ensure data protection impact assessments are current")
                recommendations.append("Verify data subject rights fulfillment processes")

            elif assessment.regulation == RegulationType.PCI_DSS:
                recommendations.append("Conduct quarterly vulnerability scans")
                recommendations.append("Review cardholder data flow documentation")

        except Exception as e:
            logging.error(f"Error generating recommendations: {e}")

        return recommendations

    async def _update_compliance_metrics(self, event: BaseEvent):
        """Update compliance metrics based on event"""
        try:
            # Track compliance-relevant events
            if event.event_type in ["audit_log_generated", "access_granted", "data_accessed"]:
                # Update compliance tracking metrics
                pass

        except Exception as e:
            logging.error(f"Error updating compliance metrics: {e}")

    async def _create_compliance_violation_event(self, trigger_event: BaseEvent, violation: Dict[str, Any]) -> BaseEvent:
        """Create compliance violation event"""
        return BaseEvent(
            event_type="compliance_violation",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.COMPLIANCE_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="compliance_engine",
            risk_score=80 if violation["severity"] == "high" else 60,
            enrichment={
                "violation": violation,
                "trigger_event": trigger_event.event_id,
                "regulation": violation["regulation"].value,
                "requirement": violation["requirement"],
                "remediation_required": True
            }
        )

    async def _create_breach_notification_event(self, trigger_event: BaseEvent, indicators: List[Dict[str, Any]]) -> BaseEvent:
        """Create breach notification event"""
        return BaseEvent(
            event_type="breach_notification_required",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.COMPLIANCE_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="compliance_engine",
            risk_score=95,
            enrichment={
                "breach_indicators": indicators,
                "trigger_event": trigger_event.event_id,
                "notification_timeline": "72_hours",
                "automated_notification": True
            }
        )

    async def cleanup(self) -> None:
        """Cleanup compliance engine"""
        try:
            logging.info("Compliance Engine cleanup completed")
        except Exception as e:
            logging.error(f"Error during compliance engine cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get compliance engine metrics"""
        return {
            **super().get_metrics(),
            "regulations_supported": len(self.regulations),
            "requirements_total": len(self.requirements),
            "controls_implemented": len(self.controls),
            "assessments_conducted": len(self.assessments),
            "active_gaps": len([g for g in self.gaps.values() if g.status != "remediated"]),
            "compliance_scores": {
                reg.value: next(
                    (a.overall_score for a in self.assessments.values() if a.regulation == reg),
                    0.0
                ) for reg in RegulationType
            }
        }


# Global instance
compliance_engine = ComplianceEngine()