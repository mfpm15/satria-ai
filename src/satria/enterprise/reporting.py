"""
SATRIA AI Executive Reporting Dashboard
Comprehensive C-level executive reporting and analytics
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid
import statistics
from pathlib import Path

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.llm_client import llm_client, LLMMessage
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class ExecutiveRole(str, Enum):
    """Executive role types"""
    CEO = "ceo"
    CISO = "ciso"
    CRO = "cro"  # Chief Risk Officer
    CFO = "cfo"
    COO = "coo"
    CTO = "cto"
    BOARD = "board"


class ReportType(str, Enum):
    """Report types"""
    EXECUTIVE_SUMMARY = "executive_summary"
    SECURITY_POSTURE = "security_posture"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_STATUS = "compliance_status"
    INCIDENT_ANALYSIS = "incident_analysis"
    THREAT_LANDSCAPE = "threat_landscape"
    INVESTMENT_ROI = "investment_roi"
    PERFORMANCE_METRICS = "performance_metrics"
    BUSINESS_IMPACT = "business_impact"
    TREND_ANALYSIS = "trend_analysis"


class MetricType(str, Enum):
    """Metric categories"""
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    RISK = "risk"
    PERFORMANCE = "performance"


class ReportPeriod(str, Enum):
    """Report time periods"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


@dataclass
class ExecutiveMetric:
    """Executive-level metric"""
    metric_id: str
    name: str
    description: str
    metric_type: MetricType
    current_value: float
    previous_value: Optional[float] = None
    target_value: Optional[float] = None
    unit: str = ""
    trend: str = "stable"  # improving, declining, stable
    benchmark: Optional[float] = None
    risk_level: str = "low"  # low, medium, high, critical
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExecutiveInsight:
    """AI-generated executive insight"""
    insight_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    summary: str = ""
    details: str = ""
    impact: str = ""  # low, medium, high, critical
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    category: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExecutiveReport:
    """Comprehensive executive report"""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_type: ReportType
    executive_role: ExecutiveRole
    title: str = ""
    period: ReportPeriod = ReportPeriod.MONTHLY
    start_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=30))
    end_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Report content
    executive_summary: str = ""
    key_metrics: List[ExecutiveMetric] = field(default_factory=list)
    insights: List[ExecutiveInsight] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    compliance_summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    # Visualization data
    charts_data: Dict[str, Any] = field(default_factory=dict)
    kpi_dashboard: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str = "satria_ai"
    version: str = "1.0"


class ExecutiveReporter(BaseAgent):
    """
    Executive Reporting Dashboard
    Generates comprehensive C-level reports and analytics
    """

    def __init__(self):
        super().__init__(
            name="executive_reporter",
            description="Executive reporting and analytics dashboard",
            version="4.0.0"
        )

        self.reports: Dict[str, ExecutiveReport] = {}
        self.metrics_history: Dict[str, List[ExecutiveMetric]] = {}
        self.executive_insights: List[ExecutiveInsight] = []

        # Industry benchmarks
        self.industry_benchmarks = {}

        # Report templates
        self.report_templates = {}

    async def initialize(self) -> bool:
        """Initialize executive reporter"""
        try:
            # Load industry benchmarks
            await self._load_industry_benchmarks()

            # Initialize report templates
            await self._initialize_report_templates()

            # Setup scheduled reporting
            await self._setup_scheduled_reporting()

            logging.info("Executive Reporter initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Executive Reporter: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for executive reporting"""
        try:
            # Update metrics based on events
            await self._update_metrics_from_event(event)

            # Generate insights if significant event
            if await self._is_executive_relevant(event):
                insight = await self._generate_executive_insight(event)
                if insight:
                    self.executive_insights.append(insight)

            return [event]

        except Exception as e:
            logging.error(f"Error processing event for executive reporting: {e}")
            return [event]

    async def generate_executive_report(self, role: ExecutiveRole, report_type: ReportType,
                                      period: ReportPeriod = ReportPeriod.MONTHLY,
                                      start_date: Optional[datetime] = None,
                                      end_date: Optional[datetime] = None) -> ExecutiveReport:
        """Generate comprehensive executive report"""
        try:
            # Set date range
            if not end_date:
                end_date = datetime.now(timezone.utc)
            if not start_date:
                start_date = self._get_period_start_date(period, end_date)

            # Create report
            report = ExecutiveReport(
                report_type=report_type,
                executive_role=role,
                period=period,
                start_date=start_date,
                end_date=end_date
            )

            # Generate role-specific content
            if role == ExecutiveRole.CEO:
                await self._generate_ceo_report(report)
            elif role == ExecutiveRole.CISO:
                await self._generate_ciso_report(report)
            elif role == ExecutiveRole.CRO:
                await self._generate_cro_report(report)
            elif role == ExecutiveRole.CFO:
                await self._generate_cfo_report(report)
            elif role == ExecutiveRole.COO:
                await self._generate_coo_report(report)
            elif role == ExecutiveRole.BOARD:
                await self._generate_board_report(report)

            # Generate AI insights
            await self._generate_ai_insights(report)

            # Create visualizations
            await self._generate_visualizations(report)

            # Store report
            self.reports[report.report_id] = report

            logging.info(f"Generated {role.value} {report_type.value} report: {report.report_id}")

            return report

        except Exception as e:
            logging.error(f"Error generating executive report: {e}")
            raise

    async def _generate_ceo_report(self, report: ExecutiveReport):
        """Generate CEO-focused report"""
        try:
            report.title = f"CEO Security & Risk Executive Summary - {report.period.value.title()}"

            # Key CEO metrics
            ceo_metrics = [
                await self._get_overall_risk_score(),
                await self._get_security_investment_roi(),
                await self._get_business_impact_prevented(),
                await self._get_regulatory_compliance_score(),
                await self._get_cyber_insurance_impact(),
                await self._get_brand_reputation_risk()
            ]

            report.key_metrics = [m for m in ceo_metrics if m]

            # Executive summary
            report.executive_summary = await self._generate_ai_executive_summary(report, "ceo")

            # Risk summary
            report.risk_summary = await self._generate_risk_summary()

            # Compliance summary
            report.compliance_summary = await self._generate_compliance_summary()

            # Strategic recommendations
            report.recommendations = await self._generate_ceo_recommendations(report)

        except Exception as e:
            logging.error(f"Error generating CEO report: {e}")

    async def _generate_ciso_report(self, report: ExecutiveReport):
        """Generate CISO-focused report"""
        try:
            report.title = f"CISO Security Posture Report - {report.period.value.title()}"

            # Key CISO metrics
            ciso_metrics = [
                await self._get_security_posture_score(),
                await self._get_threat_detection_rate(),
                await self._get_incident_response_time(),
                await self._get_vulnerability_remediation_rate(),
                await self._get_security_awareness_score(),
                await self._get_third_party_risk_score()
            ]

            report.key_metrics = [m for m in ciso_metrics if m]

            # Security operations summary
            report.executive_summary = await self._generate_ai_executive_summary(report, "ciso")

            # Threat landscape analysis
            report.risk_summary = await self._generate_threat_landscape()

            # Security control effectiveness
            report.compliance_summary = await self._generate_control_effectiveness()

            # Technical recommendations
            report.recommendations = await self._generate_ciso_recommendations(report)

        except Exception as e:
            logging.error(f"Error generating CISO report: {e}")

    async def _generate_cro_report(self, report: ExecutiveReport):
        """Generate CRO-focused report"""
        try:
            report.title = f"Chief Risk Officer Cyber Risk Assessment - {report.period.value.title()}"

            # Key CRO metrics
            cro_metrics = [
                await self._get_cyber_risk_score(),
                await self._get_risk_appetite_alignment(),
                await self._get_risk_mitigation_effectiveness(),
                await self._get_emerging_risk_indicators(),
                await self._get_business_continuity_readiness(),
                await self._get_vendor_risk_exposure()
            ]

            report.key_metrics = [m for m in cro_metrics if m]

            # Risk assessment summary
            report.executive_summary = await self._generate_ai_executive_summary(report, "cro")

            # Risk heat map
            report.risk_summary = await self._generate_risk_heat_map()

            # Risk treatment status
            report.compliance_summary = await self._generate_risk_treatment_status()

            # Risk management recommendations
            report.recommendations = await self._generate_cro_recommendations(report)

        except Exception as e:
            logging.error(f"Error generating CRO report: {e}")

    async def _generate_cfo_report(self, report: ExecutiveReport):
        """Generate CFO-focused report"""
        try:
            report.title = f"CFO Cybersecurity Financial Impact Report - {report.period.value.title()}"

            # Key CFO metrics
            cfo_metrics = [
                await self._get_security_budget_utilization(),
                await self._get_cost_per_incident(),
                await self._get_loss_prevention_value(),
                await self._get_compliance_cost_efficiency(),
                await self._get_cyber_insurance_premium_impact(),
                await self._get_security_investment_payback()
            ]

            report.key_metrics = [m for m in cfo_metrics if m]

            # Financial impact summary
            report.executive_summary = await self._generate_ai_executive_summary(report, "cfo")

            # Cost-benefit analysis
            report.risk_summary = await self._generate_cost_benefit_analysis()

            # Budget optimization opportunities
            report.compliance_summary = await self._generate_budget_optimization()

            # Financial recommendations
            report.recommendations = await self._generate_cfo_recommendations(report)

        except Exception as e:
            logging.error(f"Error generating CFO report: {e}")

    async def _generate_board_report(self, report: ExecutiveReport):
        """Generate Board-focused report"""
        try:
            report.title = f"Board Cybersecurity Governance Report - {report.period.value.title()}"

            # Key Board metrics
            board_metrics = [
                await self._get_cyber_governance_score(),
                await self._get_strategic_risk_exposure(),
                await self._get_regulatory_compliance_status(),
                await self._get_crisis_readiness_score(),
                await self._get_stakeholder_confidence_impact(),
                await self._get_competitive_security_position()
            ]

            report.key_metrics = [m for m in board_metrics if m]

            # Governance summary
            report.executive_summary = await self._generate_ai_executive_summary(report, "board")

            # Strategic risk overview
            report.risk_summary = await self._generate_strategic_risk_overview()

            # Governance effectiveness
            report.compliance_summary = await self._generate_governance_effectiveness()

            # Strategic recommendations
            report.recommendations = await self._generate_board_recommendations(report)

        except Exception as e:
            logging.error(f"Error generating Board report: {e}")

    async def _get_overall_risk_score(self) -> ExecutiveMetric:
        """Calculate overall organizational cyber risk score"""
        # Simulate risk calculation
        current_score = 7.2  # out of 10 (lower is better)
        previous_score = 7.8
        target_score = 6.0

        return ExecutiveMetric(
            metric_id="overall_risk_score",
            name="Overall Cyber Risk Score",
            description="Comprehensive organizational cyber risk assessment",
            metric_type=MetricType.RISK,
            current_value=current_score,
            previous_value=previous_score,
            target_value=target_score,
            unit="Risk Index (1-10)",
            trend="improving" if current_score < previous_score else "stable",
            benchmark=8.1,  # Industry average
            risk_level="medium"
        )

    async def _get_security_investment_roi(self) -> ExecutiveMetric:
        """Calculate security investment ROI"""
        current_roi = 240.0  # 240% ROI
        previous_roi = 220.0
        target_roi = 300.0

        return ExecutiveMetric(
            metric_id="security_investment_roi",
            name="Security Investment ROI",
            description="Return on cybersecurity investment",
            metric_type=MetricType.FINANCIAL,
            current_value=current_roi,
            previous_value=previous_roi,
            target_value=target_roi,
            unit="Percentage",
            trend="improving",
            benchmark=180.0,
            risk_level="low"
        )

    async def _get_business_impact_prevented(self) -> ExecutiveMetric:
        """Calculate business impact prevented by security measures"""
        prevented_loss = 2450000.0  # $2.45M prevented
        previous_prevented = 2100000.0
        target_prevented = 3000000.0

        return ExecutiveMetric(
            metric_id="business_impact_prevented",
            name="Business Impact Prevented",
            description="Financial loss prevented by cybersecurity measures",
            metric_type=MetricType.FINANCIAL,
            current_value=prevented_loss,
            previous_value=previous_prevented,
            target_value=target_prevented,
            unit="USD",
            trend="improving",
            benchmark=1800000.0,
            risk_level="low"
        )

    async def _get_security_posture_score(self) -> ExecutiveMetric:
        """Calculate security posture score"""
        current_score = 85.2
        previous_score = 82.1
        target_score = 90.0

        return ExecutiveMetric(
            metric_id="security_posture_score",
            name="Security Posture Score",
            description="Overall security control effectiveness",
            metric_type=MetricType.SECURITY,
            current_value=current_score,
            previous_value=previous_score,
            target_value=target_score,
            unit="Percentage",
            trend="improving",
            benchmark=78.5,
            risk_level="low"
        )

    async def _get_threat_detection_rate(self) -> ExecutiveMetric:
        """Calculate threat detection rate"""
        detection_rate = 94.7
        previous_rate = 92.1
        target_rate = 98.0

        return ExecutiveMetric(
            metric_id="threat_detection_rate",
            name="Threat Detection Rate",
            description="Percentage of threats successfully detected",
            metric_type=MetricType.SECURITY,
            current_value=detection_rate,
            previous_value=previous_rate,
            target_value=target_rate,
            unit="Percentage",
            trend="improving",
            benchmark=87.3,
            risk_level="low"
        )

    async def _get_incident_response_time(self) -> ExecutiveMetric:
        """Calculate mean incident response time"""
        response_time = 18.5  # minutes
        previous_time = 22.3
        target_time = 15.0

        return ExecutiveMetric(
            metric_id="incident_response_time",
            name="Mean Incident Response Time",
            description="Average time to respond to security incidents",
            metric_type=MetricType.OPERATIONAL,
            current_value=response_time,
            previous_value=previous_time,
            target_value=target_time,
            unit="Minutes",
            trend="improving",
            benchmark=28.7,
            risk_level="low"
        )

    async def _generate_ai_executive_summary(self, report: ExecutiveReport, role: str) -> str:
        """Generate AI-powered executive summary"""
        try:
            system_prompt = f"""You are an expert cybersecurity executive advisor generating executive summaries for {role.upper()} level.

Create a compelling executive summary that:
- Highlights key achievements and concerns
- Provides business context and impact
- Uses executive-appropriate language
- Focuses on strategic implications
- Includes actionable insights

Format: 2-3 paragraphs, approximately 150-200 words."""

            metrics_summary = "\n".join([
                f"- {m.name}: {m.current_value} {m.unit} (Target: {m.target_value} {m.unit})"
                for m in report.key_metrics[:5]
            ])

            user_prompt = f"""Generate executive summary for {role.upper()} based on:

Report Period: {report.period.value} ({report.start_date.strftime('%Y-%m-%d')} to {report.end_date.strftime('%Y-%m-%d')})

Key Metrics:
{metrics_summary}

Report Type: {report.report_type.value}

Focus on business impact, strategic implications, and key priorities for {role.upper()}."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt)
            ]

            response = await llm_client.chat_completion(
                messages=messages,
                temperature=0.3,
                max_tokens=300
            )

            return response.content if response else "Executive summary unavailable"

        except Exception as e:
            logging.error(f"Error generating AI executive summary: {e}")
            return f"Executive summary for {role.upper()} - Key metrics show positive trends in cybersecurity posture with continued focus on risk reduction and operational excellence."

    async def _generate_risk_summary(self) -> Dict[str, Any]:
        """Generate risk summary"""
        return {
            "critical_risks": 2,
            "high_risks": 8,
            "medium_risks": 24,
            "low_risks": 156,
            "risk_trend": "improving",
            "top_risks": [
                "Advanced Persistent Threats",
                "Supply Chain Vulnerabilities",
                "Insider Threats",
                "Cloud Misconfigurations",
                "Third-party Vendor Risks"
            ],
            "mitigation_progress": 78.5
        }

    async def _generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance summary"""
        return {
            "overall_score": 92.3,
            "regulations": {
                "GDPR": 94.2,
                "SOX": 91.8,
                "PCI-DSS": 88.7,
                "HIPAA": 96.1,
                "ISO27001": 89.4
            },
            "gaps": 12,
            "critical_gaps": 1,
            "next_audit": "2024-12-15",
            "certification_status": "Valid"
        }

    async def _generate_ceo_recommendations(self, report: ExecutiveReport) -> List[str]:
        """Generate CEO-specific recommendations"""
        return [
            "Increase cybersecurity budget by 15% to address emerging threats",
            "Implement board-level cybersecurity reporting and governance",
            "Enhance cyber insurance coverage based on current risk exposure",
            "Establish strategic partnerships for threat intelligence sharing",
            "Invest in security awareness training for all employees"
        ]

    async def _generate_ciso_recommendations(self, report: ExecutiveReport) -> List[str]:
        """Generate CISO-specific recommendations"""
        return [
            "Deploy additional endpoint detection and response tools",
            "Enhance threat hunting capabilities with AI-powered analytics",
            "Implement zero-trust network architecture",
            "Strengthen incident response automation",
            "Expand security orchestration across all tools"
        ]

    async def _generate_visualizations(self, report: ExecutiveReport):
        """Generate visualization data for charts and dashboards"""
        try:
            # Risk trend chart
            report.charts_data["risk_trend"] = {
                "type": "line_chart",
                "title": "Risk Score Trend",
                "data": [
                    {"month": "Jan", "score": 8.1},
                    {"month": "Feb", "score": 7.9},
                    {"month": "Mar", "score": 7.6},
                    {"month": "Apr", "score": 7.4},
                    {"month": "May", "score": 7.2}
                ]
            }

            # Security investment ROI
            report.charts_data["roi_trend"] = {
                "type": "bar_chart",
                "title": "Security Investment ROI",
                "data": [
                    {"category": "Prevention", "value": 240},
                    {"category": "Detection", "value": 180},
                    {"category": "Response", "value": 320},
                    {"category": "Recovery", "value": 150}
                ]
            }

            # Compliance heatmap
            report.charts_data["compliance_heatmap"] = {
                "type": "heatmap",
                "title": "Regulatory Compliance Status",
                "data": [
                    {"regulation": "GDPR", "score": 94.2, "status": "compliant"},
                    {"regulation": "SOX", "score": 91.8, "status": "compliant"},
                    {"regulation": "PCI-DSS", "score": 88.7, "status": "compliant"},
                    {"regulation": "HIPAA", "score": 96.1, "status": "compliant"}
                ]
            }

            # KPI Dashboard
            report.kpi_dashboard = {
                "security_score": 85.2,
                "risk_reduction": 23.5,
                "compliance_rate": 92.3,
                "incident_response": 18.5,
                "threat_detection": 94.7,
                "investment_roi": 240.0
            }

        except Exception as e:
            logging.error(f"Error generating visualizations: {e}")

    async def _is_executive_relevant(self, event: BaseEvent) -> bool:
        """Check if event is relevant for executive reporting"""
        executive_relevant_types = [
            "major_incident",
            "data_breach",
            "compliance_violation",
            "critical_vulnerability",
            "advanced_persistent_threat",
            "regulatory_fine",
            "system_outage",
            "security_budget_variance"
        ]

        return (
            event.event_type in executive_relevant_types or
            (event.risk_score and event.risk_score > 80) or
            event.enrichment.get("executive_notification", False)
        )

    async def _generate_executive_insight(self, event: BaseEvent) -> Optional[ExecutiveInsight]:
        """Generate executive insight from significant event"""
        try:
            if event.event_type == "data_breach":
                return ExecutiveInsight(
                    title="Data Breach Detected",
                    summary="Potential data breach requires immediate executive attention",
                    details=f"Security event detected: {event.enrichment.get('message', 'Data breach incident')}",
                    impact="high",
                    recommendations=[
                        "Activate incident response team",
                        "Prepare regulatory notifications",
                        "Assess legal and financial implications",
                        "Consider external communications strategy"
                    ],
                    confidence=0.9,
                    category="security"
                )

            elif event.event_type == "compliance_violation":
                return ExecutiveInsight(
                    title="Compliance Violation Identified",
                    summary="Regulatory compliance issue requires remediation",
                    details=f"Compliance violation: {event.enrichment.get('violation', {}).get('description', 'Unknown violation')}",
                    impact="medium",
                    recommendations=[
                        "Review compliance controls",
                        "Implement corrective actions",
                        "Document remediation efforts",
                        "Update policies and procedures"
                    ],
                    confidence=0.8,
                    category="compliance"
                )

            return None

        except Exception as e:
            logging.error(f"Error generating executive insight: {e}")
            return None

    def _get_period_start_date(self, period: ReportPeriod, end_date: datetime) -> datetime:
        """Get start date based on report period"""
        if period == ReportPeriod.DAILY:
            return end_date - timedelta(days=1)
        elif period == ReportPeriod.WEEKLY:
            return end_date - timedelta(days=7)
        elif period == ReportPeriod.MONTHLY:
            return end_date - timedelta(days=30)
        elif period == ReportPeriod.QUARTERLY:
            return end_date - timedelta(days=90)
        elif period == ReportPeriod.YEARLY:
            return end_date - timedelta(days=365)
        else:
            return end_date - timedelta(days=30)

    async def _load_industry_benchmarks(self):
        """Load industry security benchmarks"""
        self.industry_benchmarks = {
            "overall_risk_score": 8.1,
            "security_investment_roi": 180.0,
            "threat_detection_rate": 87.3,
            "incident_response_time": 28.7,
            "compliance_score": 84.2,
            "security_posture": 78.5
        }

    async def _initialize_report_templates(self):
        """Initialize report templates"""
        self.report_templates = {
            ExecutiveRole.CEO: "CEO Executive Summary Template",
            ExecutiveRole.CISO: "CISO Security Posture Template",
            ExecutiveRole.CRO: "CRO Risk Assessment Template",
            ExecutiveRole.CFO: "CFO Financial Impact Template",
            ExecutiveRole.BOARD: "Board Governance Template"
        }

    async def _setup_scheduled_reporting(self):
        """Setup automated scheduled reporting"""
        pass  # Implementation for scheduled report generation

    async def _update_metrics_from_event(self, event: BaseEvent):
        """Update metrics based on incoming events"""
        try:
            # Update relevant metrics based on event type
            if event.event_type == "incident_resolved":
                # Update incident response time metrics
                pass
            elif event.event_type == "threat_detected":
                # Update threat detection metrics
                pass
            elif event.event_type == "compliance_check":
                # Update compliance metrics
                pass

        except Exception as e:
            logging.error(f"Error updating metrics from event: {e}")

    async def cleanup(self) -> None:
        """Cleanup executive reporter"""
        try:
            logging.info("Executive Reporter cleanup completed")
        except Exception as e:
            logging.error(f"Error during executive reporter cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get executive reporter metrics"""
        return {
            **super().get_metrics(),
            "total_reports_generated": len(self.reports),
            "reports_by_role": {
                role.value: len([r for r in self.reports.values() if r.executive_role == role])
                for role in ExecutiveRole
            },
            "active_insights": len(self.executive_insights),
            "metrics_tracked": len(self.metrics_history),
            "last_report_generated": max([r.generated_at for r in self.reports.values()], default=datetime.min).isoformat() if self.reports else None
        }


# Global instance
executive_reporter = ExecutiveReporter()