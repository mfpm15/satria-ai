"""
SATRIA AI - Analyst Copilot
Advanced AI assistant for security analysts with natural language interface
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import uuid

# LLM and embeddings
from satria.core.llm_client import llm_client, LLMMessage

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings
from satria.agents.decision.triage_planner import triage_planner
from satria.agents.memory.incident_memory_system import incident_memory_system
from satria.agents.intelligence.threat_intelligence_engine import threat_intelligence_engine


class QueryType(str, Enum):
    """Types of analyst queries"""
    INCIDENT_ANALYSIS = "incident_analysis"
    THREAT_HUNTING = "threat_hunting"
    FORENSIC_INVESTIGATION = "forensic_investigation"
    RISK_ASSESSMENT = "risk_assessment"
    PATTERN_ANALYSIS = "pattern_analysis"
    RECOMMENDATION = "recommendation"
    COMPLIANCE_CHECK = "compliance_check"
    TREND_ANALYSIS = "trend_analysis"


class ResponseFormat(str, Enum):
    """Response format preferences"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILS = "technical_details"
    STEP_BY_STEP = "step_by_step"
    BULLET_POINTS = "bullet_points"
    GRAPH_ANALYSIS = "graph_analysis"
    TIMELINE = "timeline"


@dataclass
class AnalystQuery:
    """Analyst query structure"""
    query_id: str
    analyst_id: str
    query_text: str
    query_type: QueryType
    context: Dict[str, Any] = field(default_factory=dict)
    preferred_format: ResponseFormat = ResponseFormat.TECHNICAL_DETAILS
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    priority: str = "medium"
    session_id: Optional[str] = None


@dataclass
class CopilotResponse:
    """Copilot response structure"""
    response_id: str
    query_id: str
    response_text: str
    confidence: float
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    follow_up_questions: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time: float = 0.0


@dataclass
class AnalystSession:
    """Analyst copilot session"""
    session_id: str
    analyst_id: str
    started_at: datetime
    last_activity: datetime
    query_history: List[str] = field(default_factory=list)
    context_memory: Dict[str, Any] = field(default_factory=dict)
    active_investigation: Optional[str] = None
    preferences: Dict[str, Any] = field(default_factory=dict)


class AnalystCopilot(BaseAgent):
    """
    Advanced Analyst Copilot
    AI-powered assistant for security analysts with natural language processing
    """

    def __init__(self):
        super().__init__(
            name="analyst_copilot",
            description="AI-powered assistant for security analysts",
            version="2.0.0"
        )

        # Session management
        self.active_sessions: Dict[str, AnalystSession] = {}
        self.query_history: Dict[str, AnalystQuery] = {}
        self.response_cache: Dict[str, CopilotResponse] = {}

        # Statistics
        self.queries_processed = 0
        self.sessions_created = 0
        self.avg_response_time = 0.0

        # LLM configuration
        self.llm_model = settings.default_llm_model
        self.llm_client = None

        # Query understanding patterns
        self.query_patterns = {
            "incident_keywords": [
                "incident", "alert", "detection", "security event", "compromise",
                "breach", "attack", "malware", "suspicious"
            ],
            "threat_hunting_keywords": [
                "hunt", "search", "find", "look for", "investigate", "explore",
                "discover", "track", "trace"
            ],
            "forensic_keywords": [
                "forensic", "evidence", "timeline", "sequence", "what happened",
                "root cause", "how did", "when did", "analyze"
            ],
            "risk_keywords": [
                "risk", "assess", "evaluate", "impact", "severity", "likelihood",
                "vulnerability", "exposure"
            ]
        }

    async def initialize(self) -> bool:
        """Initialize the analyst copilot"""
        try:
            # Initialize OpenRouter LLM client
            await llm_client.initialize()

            # Initialize knowledge base
            await self._initialize_knowledge_base()

            logging.info("Analyst Copilot initialized with OpenRouter LLM")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Analyst Copilot: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for analyst copilot (not used in typical flow)"""
        # The analyst copilot typically responds to analyst queries rather than processing events
        # This method is required by BaseAgent but not used in normal operation
        return [event]

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Clear active sessions
            self.active_sessions.clear()

            # Clear query cache
            if hasattr(self, 'query_cache'):
                self.query_cache.clear()

            # Clear knowledge base
            self.knowledge_base.clear()

            self.logger.info("Analyst copilot cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    async def _test_llm_connection(self):
        """Test connection to LLM"""
        try:
            response = await self.llm_client.generate(
                model=self.llm_model,
                prompt="Test connection. Respond with 'OK'.",
                stream=False
            )
            if response and "response" in response:
                logging.info("LLM connection successful")
        except Exception as e:
            logging.warning(f"LLM connection test failed: {e}. Copilot will use fallback responses.")

    async def process_analyst_query(self, query: AnalystQuery) -> CopilotResponse:
        """Process analyst query and generate response"""
        start_time = datetime.now()
        self.queries_processed += 1

        try:
            # Classify query type if not specified
            if not query.query_type:
                query.query_type = self._classify_query(query.query_text)

            # Get session context
            session = self._get_or_create_session(query.analyst_id, query.session_id)
            session.query_history.append(query.query_id)
            session.last_activity = datetime.now(timezone.utc)

            # Gather relevant data
            context_data = await self._gather_context_data(query, session)

            # Generate response using LLM
            response_text = await self._generate_llm_response(query, context_data)

            # Extract recommendations and follow-ups
            recommendations = self._extract_recommendations(response_text)
            follow_ups = self._generate_follow_up_questions(query, context_data)

            # Calculate confidence
            confidence = self._calculate_response_confidence(context_data, response_text)

            # Create response
            processing_time = (datetime.now() - start_time).total_seconds()
            response = CopilotResponse(
                response_id=str(uuid.uuid4()),
                query_id=query.query_id,
                response_text=response_text,
                confidence=confidence,
                supporting_evidence=context_data.get("evidence", []),
                recommendations=recommendations,
                follow_up_questions=follow_ups,
                data_sources=context_data.get("sources", []),
                processing_time=processing_time
            )

            # Store response
            self.response_cache[response.response_id] = response
            self.query_history[query.query_id] = query

            # Update session context
            session.context_memory.update({
                "last_query_type": query.query_type.value,
                "last_response_id": response.response_id
            })

            # Update metrics
            self.avg_response_time = (
                (self.avg_response_time * (self.queries_processed - 1) + processing_time) /
                self.queries_processed
            )

            logging.info(f"Processed analyst query in {processing_time:.2f}s")
            return response

        except Exception as e:
            logging.error(f"Error processing analyst query: {e}")
            return self._generate_error_response(query.query_id, str(e))

    def _classify_query(self, query_text: str) -> QueryType:
        """Classify query type based on keywords and patterns"""
        query_lower = query_text.lower()

        # Score each query type
        scores = {}

        for query_type, keywords in [
            (QueryType.INCIDENT_ANALYSIS, self.query_patterns["incident_keywords"]),
            (QueryType.THREAT_HUNTING, self.query_patterns["threat_hunting_keywords"]),
            (QueryType.FORENSIC_INVESTIGATION, self.query_patterns["forensic_keywords"]),
            (QueryType.RISK_ASSESSMENT, self.query_patterns["risk_keywords"])
        ]:
            score = sum(1 for keyword in keywords if keyword in query_lower)
            scores[query_type] = score

        # Return type with highest score, default to incident analysis
        if scores:
            return max(scores, key=scores.get)
        else:
            return QueryType.INCIDENT_ANALYSIS

    def _get_or_create_session(self, analyst_id: str, session_id: Optional[str] = None) -> AnalystSession:
        """Get existing session or create new one"""
        if session_id and session_id in self.active_sessions:
            return self.active_sessions[session_id]

        # Create new session
        new_session_id = session_id or str(uuid.uuid4())
        session = AnalystSession(
            session_id=new_session_id,
            analyst_id=analyst_id,
            started_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc)
        )

        self.active_sessions[new_session_id] = session
        self.sessions_created += 1

        return session

    async def _gather_context_data(self, query: AnalystQuery, session: AnalystSession) -> Dict[str, Any]:
        """Gather relevant context data for the query"""
        context_data = {
            "evidence": [],
            "sources": [],
            "related_incidents": [],
            "threat_intelligence": [],
            "memory_insights": []
        }

        try:
            # Extract entities from query
            entities = self._extract_entities_from_query(query.query_text)

            # Get recent high-risk events
            if query.query_type in [QueryType.INCIDENT_ANALYSIS, QueryType.THREAT_HUNTING]:
                recent_events = await self._get_recent_high_risk_events(limit=10)
                context_data["evidence"].extend([{
                    "type": "recent_event",
                    "event_id": event["event_id"],
                    "risk_score": event["risk_score"],
                    "description": event.get("description", "")
                } for event in recent_events])
                context_data["sources"].append("recent_events")

            # Get active triage cases
            if query.query_type == QueryType.INCIDENT_ANALYSIS:
                active_cases = await triage_planner.get_active_cases()
                context_data["evidence"].extend([{
                    "type": "active_case",
                    "case_id": case.case_id,
                    "priority": case.priority.value,
                    "title": case.title,
                    "risk_score": case.risk_score
                } for case in active_cases[:5]])
                context_data["sources"].append("triage_cases")

            # Get memory insights
            if entities:
                entity_query = " ".join(entities)
                memory_insights = await incident_memory_system.get_memory_insights(entity_query, limit=5)
                context_data["memory_insights"] = memory_insights
                if memory_insights:
                    context_data["sources"].append("incident_memory")

            # Get threat intelligence
            if query.query_type in [QueryType.THREAT_HUNTING, QueryType.RISK_ASSESSMENT]:
                # Mock threat intel data
                context_data["threat_intelligence"] = [{
                    "indicator": "example.com",
                    "threat_score": 85,
                    "source": "threat_intel"
                }]
                context_data["sources"].append("threat_intelligence")

            return context_data

        except Exception as e:
            logging.error(f"Error gathering context data: {e}")
            return context_data

    async def _generate_llm_response(self, query: AnalystQuery, context_data: Dict[str, Any]) -> str:
        """Generate response using OpenRouter LLM"""
        try:
            # Build comprehensive prompt
            system_prompt, user_prompt = self._build_analysis_prompts(query, context_data)

            # Create messages for OpenRouter
            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt)
            ]

            # Get response from OpenRouter
            response = await llm_client.chat_completion(
                messages=messages,
                temperature=0.7,
                max_tokens=2048
            )

            if response and response.content:
                return response.content.strip()

            # Fallback response if LLM unavailable
            return self._generate_fallback_response(query, context_data)

        except Exception as e:
            logging.error(f"Error generating LLM response: {e}")
            return self._generate_fallback_response(query, context_data)

    def _build_analysis_prompts(self, query: AnalystQuery, context_data: Dict[str, Any]) -> Tuple[str, str]:
        """Build system and user prompts for LLM"""

        # System prompt
        system_prompt = """You are SATRIA AI, an advanced cybersecurity analyst assistant.
You help security analysts with incident analysis, threat hunting, and forensic investigations.
Provide detailed, actionable insights based on the available data.

Your responses should be:
- Technically accurate and specific
- Actionable with clear next steps
- Include relevant MITRE ATT&CK techniques when applicable
- Reference threat intelligence when available
- Provide risk assessment with confidence levels

Always structure your response with:
1. Executive Summary (2-3 sentences)
2. Key Findings
3. Risk Assessment (with confidence level)
4. Recommendations (prioritized)
5. Next Steps (specific actions)"""

        # User prompt with context
        user_parts = []

        # Query context
        user_parts.append(f"ANALYST QUERY:")
        user_parts.append(f"Type: {query.query_type.value}")
        user_parts.append(f"Question: {query.query_text}")

        # Context data
        if context_data["evidence"]:
            user_parts.append(f"\nAVAILABLE EVIDENCE:")
            for i, evidence in enumerate(context_data["evidence"][:5], 1):
                user_parts.append(f"{i}. {evidence['type']}: {evidence.get('description', str(evidence))}")

        if context_data["memory_insights"]:
            user_parts.append(f"\nSIMILAR PAST INCIDENTS:")
            for insight in context_data["memory_insights"][:3]:
                user_parts.append(f"- {insight['description']} (similarity: {insight['similarity']:.2f})")

        if context_data["threat_intelligence"]:
            user_parts.append(f"\nTHREAT INTELLIGENCE:")
            for intel in context_data["threat_intelligence"][:3]:
                user_parts.append(f"- {intel['indicator']}: threat score {intel['threat_score']}")

        # Response format guidance
        user_parts.append(f"\nPreferred response format: {query.preferred_format.value}")

        user_prompt = "\n".join(user_parts)

        return system_prompt, user_prompt

    def _generate_fallback_response(self, query: AnalystQuery, context_data: Dict[str, Any]) -> str:
        """Generate fallback response when LLM is unavailable"""
        response_parts = []

        response_parts.append("**SATRIA AI Analysis**")
        response_parts.append(f"Query Type: {query.query_type.value}")

        # Summary based on available data
        evidence_count = len(context_data.get("evidence", []))
        if evidence_count > 0:
            response_parts.append(f"\n**Available Evidence:** {evidence_count} items found")

            # Categorize evidence
            high_risk_count = len([e for e in context_data["evidence"]
                                 if e.get("risk_score", 0) >= 70])
            if high_risk_count > 0:
                response_parts.append(f"- {high_risk_count} high-risk items identified")

        # Memory insights
        if context_data.get("memory_insights"):
            response_parts.append(f"\n**Similar Incidents:** {len(context_data['memory_insights'])} found")
            top_insight = context_data['memory_insights'][0]
            response_parts.append(f"- Most similar: {top_insight['description'][:100]}...")

        # Basic recommendations
        response_parts.append("\n**Recommendations:**")
        if query.query_type == QueryType.INCIDENT_ANALYSIS:
            response_parts.append("1. Review high-risk events for potential incidents")
            response_parts.append("2. Correlate with similar past incidents")
            response_parts.append("3. Consider escalation if risk score > 70")
        elif query.query_type == QueryType.THREAT_HUNTING:
            response_parts.append("1. Search for IoCs in network traffic")
            response_parts.append("2. Check endpoint logs for suspicious activity")
            response_parts.append("3. Correlate with threat intelligence feeds")

        response_parts.append("\n*Note: LLM-powered analysis unavailable. Basic analysis provided.*")

        return "\n".join(response_parts)

    def _extract_entities_from_query(self, query_text: str) -> List[str]:
        """Extract entities (IPs, domains, hashes) from query text"""
        entities = []

        # IP address pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        entities.extend(re.findall(ip_pattern, query_text))

        # Domain pattern
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        potential_domains = re.findall(domain_pattern, query_text)
        # Filter out IPs that might match domain pattern
        entities.extend([d for d in potential_domains if not re.match(ip_pattern, d)])

        # Hash patterns
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            entities.extend(re.findall(pattern, query_text))

        return entities

    def _extract_recommendations(self, response_text: str) -> List[str]:
        """Extract recommendations from LLM response"""
        recommendations = []

        # Look for recommendation sections
        lines = response_text.split('\n')
        in_recommendations = False

        for line in lines:
            line = line.strip()
            if 'recommendation' in line.lower() or 'next step' in line.lower():
                in_recommendations = True
                continue

            if in_recommendations:
                if line.startswith(('1.', '2.', '3.', '-', '•')):
                    recommendation = re.sub(r'^[\d\.\-•\s]+', '', line).strip()
                    if recommendation:
                        recommendations.append(recommendation)
                elif line and not line.startswith(('#', '*')):
                    recommendations.append(line)

        return recommendations[:5]  # Limit to 5 recommendations

    def _generate_follow_up_questions(self, query: AnalystQuery, context_data: Dict[str, Any]) -> List[str]:
        """Generate relevant follow-up questions"""
        follow_ups = []

        if query.query_type == QueryType.INCIDENT_ANALYSIS:
            follow_ups.extend([
                "What was the initial attack vector?",
                "Are there any related incidents in the past 30 days?",
                "What systems were affected?",
                "Has this been escalated to the appropriate teams?"
            ])
        elif query.query_type == QueryType.THREAT_HUNTING:
            follow_ups.extend([
                "What time period should we focus on?",
                "Are there specific threat actors we should investigate?",
                "Should we expand the search to related infrastructure?",
                "What additional data sources should we examine?"
            ])
        elif query.query_type == QueryType.FORENSIC_INVESTIGATION:
            follow_ups.extend([
                "What evidence should be preserved?",
                "Do we need to create a timeline of events?",
                "Are there any compliance requirements?",
                "Should we involve external forensic specialists?"
            ])

        return follow_ups[:3]  # Limit to 3 follow-ups

    def _calculate_response_confidence(self, context_data: Dict[str, Any], response_text: str) -> float:
        """Calculate confidence in the response"""
        confidence = 0.5  # Base confidence

        # Higher confidence with more evidence
        evidence_count = len(context_data.get("evidence", []))
        confidence += min(0.3, evidence_count * 0.05)

        # Higher confidence with memory insights
        if context_data.get("memory_insights"):
            max_similarity = max([i.get("similarity", 0) for i in context_data["memory_insights"]])
            confidence += max_similarity * 0.2

        # Higher confidence with detailed response
        if len(response_text) > 500:
            confidence += 0.1

        # Check for uncertainty indicators in response
        uncertainty_words = ["might", "could", "possibly", "unclear", "unknown"]
        uncertainty_count = sum(1 for word in uncertainty_words if word in response_text.lower())
        confidence -= uncertainty_count * 0.05

        return min(0.95, max(0.1, confidence))

    def _generate_error_response(self, query_id: str, error_message: str) -> CopilotResponse:
        """Generate error response"""
        return CopilotResponse(
            response_id=str(uuid.uuid4()),
            query_id=query_id,
            response_text=f"I apologize, but I encountered an error processing your request: {error_message}",
            confidence=0.1,
            recommendations=["Please try rephrasing your question", "Check if all required data is available"]
        )

    async def _get_recent_high_risk_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent high-risk events (mock implementation)"""
        # In production, this would query the actual event store
        return [
            {
                "event_id": f"event_{i}",
                "risk_score": 80 + i,
                "description": f"High-risk security event {i}",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=i)).isoformat()
            }
            for i in range(1, limit + 1)
        ]

    async def create_analyst_session(self, analyst_id: str, preferences: Dict[str, Any] = None) -> str:
        """Create new analyst session"""
        session_id = str(uuid.uuid4())
        session = AnalystSession(
            session_id=session_id,
            analyst_id=analyst_id,
            started_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
            preferences=preferences or {}
        )

        self.active_sessions[session_id] = session
        self.sessions_created += 1

        logging.info(f"Created analyst session {session_id} for {analyst_id}")
        return session_id

    async def end_analyst_session(self, session_id: str):
        """End analyst session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logging.info(f"Ended analyst session {session_id}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get copilot metrics"""
        return {
            **super().get_metrics(),
            "queries_processed": self.queries_processed,
            "active_sessions": len(self.active_sessions),
            "sessions_created": self.sessions_created,
            "avg_response_time": self.avg_response_time,
            "cached_responses": len(self.response_cache),
            "llm_status": "active" if self.llm_client else "inactive"
        }


# Global instance
analyst_copilot = AnalystCopilot()