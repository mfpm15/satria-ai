"""
SATRIA AI Quantum Decision Engine (QDE)
Probabilistic superposition for Red/Blue team persona selection and action planning
"""

import asyncio
import logging
import random
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from dataclasses import dataclass, field
import json

from satria.models.events import BaseEvent, Severity, Confidence, AttackTechnique
from satria.core.config import settings


class Persona(str, Enum):
    """QDE Personas"""
    ELLIOT = "elliot"  # Red team persona - proactive, hunting
    MR_ROBOT = "mr_robot"  # Blue team persona - defensive, reactive
    PURPLE_TEAM = "purple_team"  # Purple team - collaborative validation
    THREAT_HUNTER = "threat_hunter"  # Advanced hunting persona
    INCIDENT_COMMANDER = "incident_commander"  # Crisis management persona
    COMPLIANCE_OFFICER = "compliance_officer"  # Regulatory compliance focused
    BALANCED = "balanced"  # Hybrid approach


class DecisionStage(str, Enum):
    """Incident response stages"""
    OBSERVATION = "observation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class ActionPriority(str, Enum):
    """Action execution priority"""
    P0_CRITICAL = "p0_critical"  # Immediate execution
    P1_HIGH = "p1_high"         # Within 15 minutes
    P2_MEDIUM = "p2_medium"     # Within 1 hour
    P3_LOW = "p3_low"           # Within 4 hours


@dataclass
class DecisionContext:
    """Context for QDE decision making"""
    risk_score: float  # 0.0-1.0
    confidence: float  # 0.0-1.0
    business_impact: str  # LOW, MEDIUM, HIGH, CRITICAL
    attack_stage: str  # MITRE ATT&CK tactic
    affected_entities: List[str]
    policy_flags: Dict[str, bool] = field(default_factory=dict)
    time_pressure: float = 0.5  # 0.0-1.0, urgency factor
    historical_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PersonaMix:
    """Persona probability distribution"""
    persona_weights: Dict[str, float]  # All persona weights
    dominant_persona: Persona
    secondary_persona: Optional[Persona]
    confidence: float
    reasoning: str
    collaboration_score: float = 0.0  # Purple team collaboration factor


@dataclass
class ActionPlan:
    """QDE generated action plan"""
    plan_id: str
    stage: DecisionStage
    actions: List[Dict[str, Any]]
    priority: ActionPriority
    estimated_duration: timedelta
    rollback_plan: List[Dict[str, Any]]
    approval_required: bool
    safety_score: float  # 0.0-1.0
    blast_radius: str  # Estimated impact scope


@dataclass
class QDEDecision:
    """Complete QDE decision output"""
    decision_id: str
    persona_mix: PersonaMix
    action_plan: ActionPlan
    reasoning: str
    timestamp: datetime
    context: DecisionContext
    guardrails_passed: bool
    simulation_results: Optional[Dict[str, Any]] = None


class QuantumDecisionEngine:
    """
    SATRIA Quantum Decision Engine

    Implements probabilistic superposition for persona selection:
    |S⟩ = α|Blue⟩ + β|Red⟩ where |α|²+|β|²=1
    """

    def __init__(self):
        self.logger = logging.getLogger("satria.qde")

        # Advanced calibration parameters
        self.persona_base_weights = {
            Persona.MR_ROBOT: 0.25,  # Defensive baseline
            Persona.ELLIOT: 0.20,  # Proactive hunting
            Persona.PURPLE_TEAM: 0.20,  # Collaborative validation
            Persona.THREAT_HUNTER: 0.15,  # Advanced hunting
            Persona.INCIDENT_COMMANDER: 0.10,  # Crisis management
            Persona.COMPLIANCE_OFFICER: 0.05,  # Regulatory focus
            Persona.BALANCED: 0.05  # Fallback hybrid
        }

        self.risk_sensitivity = 0.8
        self.confidence_threshold = 0.7
        self.collaboration_threshold = 0.6

        # Enhanced policy constraints
        self.policy_gates = {
            "maintenance_window": False,
            "critical_service_protection": True,
            "approval_required_threshold": 0.8,
            "auto_action_enabled": True,
            "purple_team_validation": True,
            "compliance_mode": False,
            "threat_hunting_enabled": True,
            "crisis_mode": False
        }

        # Historical decisions for learning
        self.decision_history: List[QDEDecision] = []
        self.persona_performance: Dict[Persona, Dict[str, float]] = {}

        # Dynamic learning factors
        self.decision_factors = {
            "risk_factor": 0.25,
            "confidence_factor": 0.20,
            "business_impact_factor": 0.20,
            "time_pressure_factor": 0.15,
            "historical_factor": 0.10,
            "collaboration_factor": 0.10
        }

    async def decide(self, context: DecisionContext) -> QDEDecision:
        """
        Main decision function - quantum superposition selection
        """
        try:
            # Calculate persona mix using probabilistic superposition
            persona_mix = await self._calculate_persona_superposition(context)

            # Generate action plan based on dominant persona
            action_plan = await self._generate_action_plan(context, persona_mix)

            # Apply safety guardrails
            guardrails_passed, action_plan = await self._apply_safety_guardrails(action_plan, context)

            # Create decision object
            decision = QDEDecision(
                decision_id=f"qde-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}",
                persona_mix=persona_mix,
                action_plan=action_plan,
                reasoning=await self._generate_reasoning(context, persona_mix),
                timestamp=datetime.utcnow(),
                context=context,
                guardrails_passed=guardrails_passed
            )

            # Store for learning
            self.decision_history.append(decision)

            self.logger.info(f"QDE Decision {decision.decision_id}: {persona_mix.dominant_persona.value} "
                           f"(risk={context.risk_score:.2f}, conf={context.confidence:.2f})")

            return decision

        except Exception as e:
            self.logger.error(f"QDE decision error: {e}")
            return await self._create_fallback_decision(context)

    async def _calculate_persona_superposition(self, context: DecisionContext) -> PersonaMix:
        """
        Calculate advanced multi-persona superposition
        |S⟩ = Σ αᵢ|Personaᵢ⟩ where Σ|αᵢ|² = 1
        """
        # Base factors for persona calculation
        factors = {
            "risk": self._calculate_risk_factor(context.risk_score),
            "confidence": self._calculate_confidence_factor(context.confidence),
            "business_impact": self._calculate_business_impact_factor(context.business_impact),
            "time_pressure": self._calculate_time_pressure_factor(context.time_pressure),
            "historical": self._calculate_historical_factor(context),
            "collaboration": self._calculate_collaboration_factor(context)
        }

        # Calculate weights for each persona
        persona_scores = {}
        for persona in Persona:
            score = self._calculate_persona_score(persona, factors, context)
            persona_scores[persona] = score

        # Normalize weights
        total_score = sum(persona_scores.values())
        if total_score > 0:
            persona_weights = {p: s/total_score for p, s in persona_scores.items()}
        else:
            persona_weights = {p: 1.0/len(Persona) for p in Persona}

        # Select dominant and secondary personas
        sorted_personas = sorted(persona_weights.items(), key=lambda x: x[1], reverse=True)
        dominant_persona = sorted_personas[0][0]
        secondary_persona = sorted_personas[1][0] if len(sorted_personas) > 1 else None

        # Calculate decision confidence
        decision_confidence = sorted_personas[0][1] - sorted_personas[1][1] if len(sorted_personas) > 1 else 1.0

        # Calculate collaboration score
        collaboration_score = self._calculate_collaboration_score(dominant_persona, secondary_persona, context)

        reasoning = self._explain_advanced_persona_selection(factors, sorted_personas[:3])

        return PersonaMix(
            persona_weights={p.value: w for p, w in persona_weights.items()},
            dominant_persona=dominant_persona,
            secondary_persona=secondary_persona,
            confidence=decision_confidence,
            reasoning=reasoning,
            collaboration_score=collaboration_score
        )

    def _calculate_risk_factor(self, risk_score: float) -> float:
        """High risk → more Blue (defensive)"""
        return min(risk_score * 1.5, 1.0)

    def _calculate_confidence_factor(self, confidence: float) -> float:
        """High confidence → can afford Red (proactive)"""
        return 1.0 - confidence

    def _calculate_business_impact_factor(self, impact: str) -> float:
        """High business impact → more Blue (safe)"""
        impact_weights = {
            "LOW": 0.2,
            "MEDIUM": 0.5,
            "HIGH": 0.8,
            "CRITICAL": 1.0
        }
        return impact_weights.get(impact.upper(), 0.5)

    def _calculate_time_pressure_factor(self, time_pressure: float) -> float:
        """High time pressure → more Blue (proven responses)"""
        return time_pressure

    def _calculate_historical_factor(self, context: DecisionContext) -> float:
        """Learn from past decisions"""
        if not self.decision_history:
            return 0.5

        # Find similar past contexts
        similar_decisions = [
            d for d in self.decision_history[-50:]  # Last 50 decisions
            if abs(d.context.risk_score - context.risk_score) < 0.2
            and d.context.business_impact == context.business_impact
        ]

        if not similar_decisions:
            return 0.5

        # Calculate success rate for each persona
        persona_performance = {}
        for persona in Persona:
            persona_decisions = [d for d in similar_decisions if d.persona_mix.dominant_persona == persona]
            if persona_decisions:
                # Simulate success rate (in production, would use actual feedback)
                success_rate = 0.8 if persona == Persona.MR_ROBOT else 0.75
                persona_performance[persona] = success_rate

        return max(persona_performance.values()) if persona_performance else 0.5

    def _calculate_collaboration_factor(self, context: DecisionContext) -> float:
        """Calculate need for collaborative approach"""
        collaboration_indicators = [
            context.risk_score > 0.7,  # High risk benefits from validation
            context.business_impact in ["HIGH", "CRITICAL"],  # High impact needs multiple perspectives
            len(context.affected_entities) > 5,  # Complex incidents need collaboration
            "advanced_persistent_threat" in context.attack_stage.lower()  # APT needs purple team
        ]

        return sum(collaboration_indicators) / len(collaboration_indicators)

    def _calculate_persona_score(self, persona: Persona, factors: Dict[str, float], context: DecisionContext) -> float:
        """Calculate score for specific persona based on context"""
        base_weight = self.persona_base_weights.get(persona, 0.1)

        # Persona-specific factor adjustments
        if persona == Persona.MR_ROBOT:
            # Defensive persona - favors high risk, proven responses
            score = base_weight * (1.0 + factors["risk"] + factors["business_impact"])

        elif persona == Persona.ELLIOT:
            # Proactive hunting - favors medium risk, high confidence
            score = base_weight * (1.0 + factors["confidence"] + (1.0 - factors["time_pressure"]))

        elif persona == Persona.PURPLE_TEAM:
            # Collaborative validation - favors complex scenarios
            score = base_weight * (1.0 + factors["collaboration"] + factors["risk"])

        elif persona == Persona.THREAT_HUNTER:
            # Advanced hunting - favors early stage, low time pressure
            score = base_weight * (1.0 + factors["confidence"] + (1.0 - factors["time_pressure"]))
            if "Initial Access" in context.attack_stage or "Reconnaissance" in context.attack_stage:
                score *= 1.5

        elif persona == Persona.INCIDENT_COMMANDER:
            # Crisis management - favors high impact, time pressure
            score = base_weight * (1.0 + factors["business_impact"] + factors["time_pressure"])
            if self.policy_gates.get("crisis_mode", False):
                score *= 2.0

        elif persona == Persona.COMPLIANCE_OFFICER:
            # Regulatory focus - favors when compliance mode active
            score = base_weight
            if self.policy_gates.get("compliance_mode", False):
                score *= 3.0
            if "data_exfiltration" in context.attack_stage.lower():
                score *= 1.5

        else:  # BALANCED
            score = base_weight * sum(factors.values()) / len(factors)

        return max(0.0, score)

    def _calculate_collaboration_score(self, dominant: Persona, secondary: Optional[Persona], context: DecisionContext) -> float:
        """Calculate collaboration effectiveness score"""
        if not secondary:
            return 0.0

        # Purple team combinations are highly collaborative
        if dominant == Persona.PURPLE_TEAM or secondary == Persona.PURPLE_TEAM:
            return 0.9

        # Red-Blue collaboration
        if {dominant, secondary} == {Persona.ELLIOT, Persona.MR_ROBOT}:
            return 0.8

        # Threat Hunter + Incident Commander
        if {dominant, secondary} == {Persona.THREAT_HUNTER, Persona.INCIDENT_COMMANDER}:
            return 0.7

        return 0.5

    def _explain_advanced_persona_selection(self, factors: Dict[str, float], top_personas: List[Tuple[Persona, float]]) -> str:
        """Generate human-readable reasoning for advanced persona selection"""
        dominant_persona, dominant_weight = top_personas[0]
        secondary_persona, secondary_weight = top_personas[1] if len(top_personas) > 1 else (None, 0)

        # Identify key factors
        dominant_factors = sorted(factors.items(), key=lambda x: x[1], reverse=True)[:2]
        factor_descriptions = []

        for factor, value in dominant_factors:
            if value > 0.7:
                factor_descriptions.append(f"High {factor} ({value:.2f})")
            elif value < 0.3:
                factor_descriptions.append(f"Low {factor} ({value:.2f})")
            else:
                factor_descriptions.append(f"Moderate {factor} ({value:.2f})")

        # Persona explanations
        persona_descriptions = {
            Persona.MR_ROBOT: "defensive/reactive approach",
            Persona.ELLIOT: "proactive hunting approach",
            Persona.PURPLE_TEAM: "collaborative validation approach",
            Persona.THREAT_HUNTER: "advanced hunting approach",
            Persona.INCIDENT_COMMANDER: "crisis management approach",
            Persona.COMPLIANCE_OFFICER: "regulatory compliance approach",
            Persona.BALANCED: "balanced hybrid approach"
        }

        primary_desc = persona_descriptions.get(dominant_persona, "unknown approach")
        confidence_desc = "high" if dominant_weight > 0.6 else "moderate" if dominant_weight > 0.4 else "low"

        reasoning = f"{primary_desc.title()} selected with {confidence_desc} confidence ({dominant_weight:.2f})"

        if secondary_persona and secondary_weight > 0.2:
            secondary_desc = persona_descriptions.get(secondary_persona, "unknown")
            reasoning += f" with {secondary_desc} support ({secondary_weight:.2f})"

        reasoning += f". Key factors: {', '.join(factor_descriptions)}"

        return reasoning

    async def _generate_action_plan(self, context: DecisionContext, persona_mix: PersonaMix) -> ActionPlan:
        """Generate action plan based on persona and context"""
        plan_id = f"plan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Determine stage based on attack progression
        stage = self._determine_stage(context)

        # Generate actions based on persona
        actions = await self._generate_persona_actions(context, persona_mix, stage)

        # Determine priority
        priority = self._calculate_priority(context)

        # Create rollback plan
        rollback_plan = self._generate_rollback_plan(actions)

        # Calculate safety score
        safety_score = self._calculate_safety_score(actions, context)

        return ActionPlan(
            plan_id=plan_id,
            stage=stage,
            actions=actions,
            priority=priority,
            estimated_duration=timedelta(minutes=self._estimate_duration(actions)),
            rollback_plan=rollback_plan,
            approval_required=safety_score < 0.7 or context.business_impact in ["HIGH", "CRITICAL"],
            safety_score=safety_score,
            blast_radius=self._estimate_blast_radius(actions)
        )

    def _determine_stage(self, context: DecisionContext) -> DecisionStage:
        """Determine appropriate response stage"""
        # Early stage detection
        early_stage_tactics = ["Initial Access", "Execution", "Persistence"]
        if context.attack_stage in early_stage_tactics:
            return DecisionStage.OBSERVATION

        # Active threat
        active_tactics = ["Privilege Escalation", "Defense Evasion", "Credential Access"]
        if context.attack_stage in active_tactics:
            return DecisionStage.CONTAINMENT

        # Advanced threat
        advanced_tactics = ["Discovery", "Lateral Movement", "Collection"]
        if context.attack_stage in advanced_tactics:
            return DecisionStage.ERADICATION

        # Damage control
        if context.attack_stage in ["Exfiltration", "Impact"]:
            return DecisionStage.RECOVERY

        return DecisionStage.OBSERVATION

    async def _generate_persona_actions(self, context: DecisionContext, persona_mix: PersonaMix,
                                      stage: DecisionStage) -> List[Dict[str, Any]]:
        """Generate actions based on dominant and secondary personas"""
        actions = []

        # Primary actions from dominant persona
        if persona_mix.dominant_persona == Persona.MR_ROBOT:
            actions.extend(self._get_blue_team_actions(context, stage))
        elif persona_mix.dominant_persona == Persona.ELLIOT:
            actions.extend(self._get_red_team_actions(context, stage))
        elif persona_mix.dominant_persona == Persona.PURPLE_TEAM:
            actions.extend(self._get_purple_team_actions(context, stage))
        elif persona_mix.dominant_persona == Persona.THREAT_HUNTER:
            actions.extend(self._get_threat_hunter_actions(context, stage))
        elif persona_mix.dominant_persona == Persona.INCIDENT_COMMANDER:
            actions.extend(self._get_incident_commander_actions(context, stage))
        elif persona_mix.dominant_persona == Persona.COMPLIANCE_OFFICER:
            actions.extend(self._get_compliance_officer_actions(context, stage))
        else:
            actions.extend(self._get_balanced_actions(context, stage))

        # Secondary actions if collaboration score is high
        if (persona_mix.secondary_persona and
            persona_mix.collaboration_score > self.collaboration_threshold):
            secondary_actions = self._get_secondary_persona_actions(
                persona_mix.secondary_persona, context, stage
            )
            # Limit secondary actions to avoid overload
            actions.extend(secondary_actions[:2])

        return actions

    def _get_blue_team_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Traditional blue team defensive actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "siem.correlate", "entities": context.affected_entities, "ttl": "1h"},
                {"op": "threat_intel.enrich", "indicators": context.affected_entities},
                {"op": "analyst.notify", "severity": "info", "requires_action": False}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            if context.risk_score > 0.7:
                actions.extend([
                    {"op": "edr.isolate", "hosts": context.affected_entities, "ttl": "4h"},
                    {"op": "network.block_ip", "ips": context.affected_entities, "ttl": "24h"},
                    {"op": "iam.disable_user", "users": context.affected_entities, "ttl": "24h"}
                ])

        elif stage == DecisionStage.ERADICATION:
            actions.extend([
                {"op": "edr.scan_full", "hosts": context.affected_entities},
                {"op": "patch.emergency_deploy", "cves": context.historical_context.get("cves", [])},
                {"op": "forensics.collect", "hosts": context.affected_entities}
            ])

        return actions

    def _get_red_team_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Proactive red team hunting actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "hunt.anomaly_scan", "scope": "network", "intensity": "high"},
                {"op": "deception.deploy_canaries", "count": 3, "types": ["file", "service", "creds"]},
                {"op": "threat_hunt.behavioral", "entities": context.affected_entities}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            actions.extend([
                {"op": "hunt.lateral_movement", "pivot_hosts": context.affected_entities},
                {"op": "network.micro_segment", "hosts": context.affected_entities, "ttl": "12h"},
                {"op": "edr.process_tree_analysis", "hosts": context.affected_entities}
            ])

        return actions

    def _get_purple_team_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Purple team collaborative validation actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "purple.validate_detection", "indicators": context.affected_entities, "confidence_threshold": 0.8},
                {"op": "purple.test_defenses", "scope": "limited", "techniques": ["T1059", "T1055"]},
                {"op": "purple.collaborative_hunt", "teams": ["red", "blue"], "duration": "2h"}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            actions.extend([
                {"op": "purple.validate_containment", "entities": context.affected_entities},
                {"op": "purple.test_bypass", "containment_measures": ["isolation", "blocking"]},
                {"op": "purple.effectiveness_assessment", "metrics": ["detection_time", "response_time"]}
            ])

        return actions

    def _get_threat_hunter_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Advanced threat hunting actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "hunt.advanced_analytics", "techniques": ["behavior_analysis", "ml_anomaly"]},
                {"op": "hunt.threat_landscape", "scope": "campaign_analysis", "lookback": "30d"},
                {"op": "hunt.attribution", "indicators": context.affected_entities, "ttp_mapping": True}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            actions.extend([
                {"op": "hunt.lateral_analysis", "pivot_points": context.affected_entities},
                {"op": "hunt.persistence_check", "mechanisms": ["registry", "scheduled_tasks", "services"]},
                {"op": "hunt.c2_analysis", "network_indicators": context.affected_entities}
            ])

        return actions

    def _get_incident_commander_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Crisis management and coordination actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "command.situation_assessment", "scope": "enterprise", "urgency": "high"},
                {"op": "command.stakeholder_notification", "levels": ["management", "legal", "pr"]},
                {"op": "command.resource_mobilization", "teams": ["ir", "forensics", "legal"]}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            actions.extend([
                {"op": "command.coordinate_response", "teams": ["blue", "red", "forensics"]},
                {"op": "command.escalation_management", "triggers": ["business_impact", "data_loss"]},
                {"op": "command.communication_plan", "channels": ["internal", "external", "regulatory"]}
            ])

        return actions

    def _get_compliance_officer_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Regulatory compliance focused actions"""
        actions = []

        if stage == DecisionStage.OBSERVATION:
            actions.extend([
                {"op": "compliance.breach_assessment", "regulations": ["gdpr", "pci", "sox", "hipaa"]},
                {"op": "compliance.notification_requirements", "jurisdictions": ["eu", "us", "local"]},
                {"op": "compliance.evidence_preservation", "retention_policy": "legal_hold"}
            ])

        elif stage == DecisionStage.CONTAINMENT:
            actions.extend([
                {"op": "compliance.data_impact_assessment", "data_types": ["pii", "phi", "financial"]},
                {"op": "compliance.regulatory_reporting", "timeline": "72h", "scope": "affected_records"},
                {"op": "compliance.audit_trail", "actions": "all_response_actions", "format": "immutable"}
            ])

        return actions

    def _get_secondary_persona_actions(self, persona: Persona, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Get supporting actions from secondary persona"""
        if persona == Persona.MR_ROBOT:
            return self._get_blue_team_actions(context, stage)[:1]  # Limited blue actions
        elif persona == Persona.ELLIOT:
            return self._get_red_team_actions(context, stage)[:1]  # Limited red actions
        elif persona == Persona.PURPLE_TEAM:
            return self._get_purple_team_actions(context, stage)[:1]
        elif persona == Persona.THREAT_HUNTER:
            return self._get_threat_hunter_actions(context, stage)[:1]
        elif persona == Persona.INCIDENT_COMMANDER:
            return self._get_incident_commander_actions(context, stage)[:1]
        elif persona == Persona.COMPLIANCE_OFFICER:
            return self._get_compliance_officer_actions(context, stage)[:1]
        else:
            return []

    def _get_balanced_actions(self, context: DecisionContext, stage: DecisionStage) -> List[Dict[str, Any]]:
        """Hybrid approach combining multiple personas"""
        blue_actions = self._get_blue_team_actions(context, stage)[:1]
        red_actions = self._get_red_team_actions(context, stage)[:1]
        purple_actions = self._get_purple_team_actions(context, stage)[:1]

        # Balanced mix of different approaches
        return blue_actions + red_actions + purple_actions

    def _calculate_priority(self, context: DecisionContext) -> ActionPriority:
        """Calculate action priority"""
        if context.business_impact == "CRITICAL" or context.risk_score > 0.9:
            return ActionPriority.P0_CRITICAL
        elif context.business_impact == "HIGH" or context.risk_score > 0.7:
            return ActionPriority.P1_HIGH
        elif context.risk_score > 0.4:
            return ActionPriority.P2_MEDIUM
        else:
            return ActionPriority.P3_LOW

    def _generate_rollback_plan(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate rollback plan for actions"""
        rollback = []

        for action in actions:
            op = action.get("op", "")

            if op == "edr.isolate":
                rollback.append({"op": "edr.release", "hosts": action.get("hosts", [])})
            elif op == "network.block_ip":
                rollback.append({"op": "network.unblock_ip", "ips": action.get("ips", [])})
            elif op == "iam.disable_user":
                rollback.append({"op": "iam.enable_user", "users": action.get("users", [])})
            # Add more rollback mappings as needed

        return rollback

    def _calculate_safety_score(self, actions: List[Dict[str, Any]], context: DecisionContext) -> float:
        """Calculate safety score for action plan (0.0-1.0)"""
        base_score = 1.0

        # Penalize risky actions
        risky_ops = ["edr.isolate", "network.block_ip", "iam.disable_user", "patch.emergency_deploy"]

        for action in actions:
            op = action.get("op", "")
            if op in risky_ops:
                base_score -= 0.1

        # Consider context
        if context.business_impact == "CRITICAL":
            base_score -= 0.2

        return max(0.0, min(1.0, base_score))

    def _estimate_duration(self, actions: List[Dict[str, Any]]) -> int:
        """Estimate duration in minutes"""
        durations = {
            "siem.correlate": 5,
            "edr.isolate": 10,
            "network.block_ip": 5,
            "iam.disable_user": 5,
            "forensics.collect": 30,
            "hunt.anomaly_scan": 20
        }

        total = sum(durations.get(action.get("op", ""), 10) for action in actions)
        return max(15, total)  # Minimum 15 minutes

    def _estimate_blast_radius(self, actions: List[Dict[str, Any]]) -> str:
        """Estimate blast radius of actions"""
        high_impact_ops = ["edr.isolate", "network.block_ip", "iam.disable_user"]

        if any(action.get("op", "") in high_impact_ops for action in actions):
            return "HIGH"
        else:
            return "LOW"

    async def _apply_safety_guardrails(self, action_plan: ActionPlan,
                                     context: DecisionContext) -> Tuple[bool, ActionPlan]:
        """Apply safety guardrails to action plan"""
        # Check policy gates
        if not self.policy_gates["auto_action_enabled"]:
            action_plan.approval_required = True

        if self.policy_gates["maintenance_window"]:
            action_plan.approval_required = True

        if context.business_impact == "CRITICAL" and self.policy_gates["critical_service_protection"]:
            action_plan.approval_required = True

        # Safety score threshold
        if action_plan.safety_score < self.policy_gates["approval_required_threshold"]:
            action_plan.approval_required = True

        # All guardrails passed if no approval required
        guardrails_passed = not action_plan.approval_required

        return guardrails_passed, action_plan

    async def _generate_reasoning(self, context: DecisionContext, persona_mix: PersonaMix) -> str:
        """Generate human-readable reasoning for decision"""
        reasoning_parts = [
            f"Risk assessment: {context.risk_score:.1%}",
            f"Confidence level: {context.confidence:.1%}",
            f"Business impact: {context.business_impact}",
            f"Attack stage: {context.attack_stage}",
            f"Persona selection: {persona_mix.reasoning}"
        ]

        return " | ".join(reasoning_parts)

    async def _create_fallback_decision(self, context: DecisionContext) -> QDEDecision:
        """Create safe fallback decision on error"""
        fallback_mix = PersonaMix(
            elliot_weight=0.0,
            mr_robot_weight=1.0,
            dominant_persona=Persona.MR_ROBOT,
            confidence=1.0,
            reasoning="Fallback to safe Blue team approach due to QDE error"
        )

        fallback_plan = ActionPlan(
            plan_id=f"fallback-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            stage=DecisionStage.OBSERVATION,
            actions=[{"op": "analyst.notify", "message": "Manual review required"}],
            priority=ActionPriority.P1_HIGH,
            estimated_duration=timedelta(minutes=5),
            rollback_plan=[],
            approval_required=True,
            safety_score=1.0,
            blast_radius="NONE"
        )

        return QDEDecision(
            decision_id=f"fallback-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            persona_mix=fallback_mix,
            action_plan=fallback_plan,
            reasoning="QDE fallback - manual review required",
            timestamp=datetime.utcnow(),
            context=context,
            guardrails_passed=True
        )

    def update_policy_gates(self, gates: Dict[str, bool]) -> None:
        """Update policy gates configuration"""
        self.policy_gates.update(gates)
        self.logger.info(f"Updated policy gates: {gates}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get QDE performance metrics"""
        recent_decisions = self.decision_history[-100:]  # Last 100 decisions

        if not recent_decisions:
            return {"decisions_count": 0}

        persona_distribution = {}
        for persona in Persona:
            count = sum(1 for d in recent_decisions if d.persona_mix.dominant_persona == persona)
            persona_distribution[persona.value] = count

        avg_safety_score = sum(d.action_plan.safety_score for d in recent_decisions) / len(recent_decisions)
        approval_rate = sum(1 for d in recent_decisions if d.action_plan.approval_required) / len(recent_decisions)

        return {
            "decisions_count": len(self.decision_history),
            "recent_decisions": len(recent_decisions),
            "persona_distribution": persona_distribution,
            "avg_safety_score": avg_safety_score,
            "approval_rate": approval_rate,
            "policy_gates": self.policy_gates
        }


# Global QDE instance
qde = QuantumDecisionEngine()