"""
SATRIA AI - Enhanced API Endpoints for Phase 2
New endpoints for intelligence, memory, and copilot features
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from satria.api.security import verify_token
from satria.agents.intelligence.behavioral_anomaly_detector import behavioral_anomaly_detector
from satria.agents.intelligence.network_anomaly_detector import network_anomaly_detector
from satria.agents.intelligence.threat_intelligence_engine import threat_intelligence_engine
from satria.agents.memory.incident_memory_system import incident_memory_system
from satria.agents.copilot.analyst_copilot import analyst_copilot, AnalystQuery, QueryType, ResponseFormat
from satria.core.enhanced_methods import enhance_orchestrator


# Create enhanced router
enhanced_router = APIRouter(prefix="/v2", tags=["Enhanced Intelligence"])

# Enhance the orchestrator
enhance_orchestrator()


# Pydantic models for requests/responses
class AnomalyAnalysisRequest(BaseModel):
    """Request for anomaly analysis"""
    entity_type: str = Field(..., description="Entity type (user, host, ip)")
    entity_id: str = Field(..., description="Entity identifier")
    time_window_hours: int = Field(default=24, description="Analysis time window")
    include_behavioral: bool = Field(default=True, description="Include behavioral analysis")
    include_network: bool = Field(default=True, description="Include network analysis")


class ThreatIntelRequest(BaseModel):
    """Request for threat intelligence lookup"""
    indicators: List[str] = Field(..., description="List of indicators to analyze")
    indicator_types: Optional[List[str]] = Field(default=None, description="Filter by indicator types")
    include_context: bool = Field(default=True, description="Include contextual information")


class MemoryQueryRequest(BaseModel):
    """Request for memory system query"""
    query: str = Field(..., description="Natural language query")
    limit: int = Field(default=10, description="Maximum results to return")
    similarity_threshold: float = Field(default=0.7, description="Minimum similarity threshold")


class AnalystCopilotRequest(BaseModel):
    """Request for analyst copilot"""
    query: str = Field(..., description="Analyst question or request")
    query_type: Optional[QueryType] = Field(default=None, description="Query type")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    preferred_format: ResponseFormat = Field(default=ResponseFormat.TECHNICAL_DETAILS)
    session_id: Optional[str] = Field(default=None, description="Session ID for context")


# Enhanced Intelligence Endpoints
@enhanced_router.post("/intelligence/anomaly-analysis")
async def analyze_anomalies(
    request: AnomalyAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Perform comprehensive anomaly analysis"""
    try:
        await verify_token(credentials.credentials)

        results = {
            "entity_type": request.entity_type,
            "entity_id": request.entity_id,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "behavioral_analysis": None,
            "network_analysis": None,
            "overall_risk_score": 0,
            "anomalies_detected": []
        }

        # Behavioral anomaly analysis
        if request.include_behavioral:
            behavioral_metrics = behavioral_anomaly_detector.get_metrics()
            results["behavioral_analysis"] = {
                "status": "healthy" if behavioral_anomaly_detector.is_running else "inactive",
                "profiles_analyzed": behavioral_metrics.get("behavioral_profiles", 0),
                "anomalies_detected": behavioral_metrics.get("anomalies_detected", 0),
                "active_models": behavioral_metrics.get("active_models", 0)
            }

        # Network anomaly analysis
        if request.include_network:
            network_metrics = network_anomaly_detector.get_metrics()
            results["network_analysis"] = {
                "status": "healthy" if network_anomaly_detector.is_running else "inactive",
                "flows_analyzed": network_metrics.get("flows_processed", 0),
                "anomalies_detected": network_metrics.get("anomalies_detected", 0),
                "beacon_candidates": network_metrics.get("beacon_candidates", 0)
            }

        # Calculate overall risk
        behavioral_risk = results["behavioral_analysis"].get("anomalies_detected", 0) * 10 if results["behavioral_analysis"] else 0
        network_risk = results["network_analysis"].get("anomalies_detected", 0) * 15 if results["network_analysis"] else 0
        results["overall_risk_score"] = min(100, behavioral_risk + network_risk)

        return results

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly analysis error: {str(e)}"
        )


@enhanced_router.post("/intelligence/threat-intel")
async def threat_intelligence_lookup(
    request: ThreatIntelRequest,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Perform threat intelligence lookup"""
    try:
        await verify_token(credentials.credentials)

        # Get threat intel engine metrics
        intel_metrics = threat_intelligence_engine.get_metrics()

        # Mock enrichment results for demo
        enrichment_results = []
        for indicator in request.indicators:
            enrichment_results.append({
                "indicator": indicator,
                "threat_score": 0,  # Would be calculated by actual enrichment
                "sources": [],
                "last_seen": None,
                "tags": []
            })

        return {
            "indicators_analyzed": len(request.indicators),
            "enrichment_results": enrichment_results,
            "threat_intel_stats": {
                "requests_processed": intel_metrics.get("enrichment_requests", 0),
                "hit_rate": intel_metrics.get("hit_rate", 0.0),
                "cached_indicators": intel_metrics.get("cached_enrichments", 0)
            },
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat intelligence error: {str(e)}"
        )


@enhanced_router.post("/memory/query")
async def query_incident_memory(
    request: MemoryQueryRequest,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Query incident memory system"""
    try:
        await verify_token(credentials.credentials)

        # Query memory system
        insights = await incident_memory_system.get_memory_insights(
            request.query,
            limit=request.limit
        )

        memory_metrics = incident_memory_system.get_metrics()

        return {
            "query": request.query,
            "insights_found": len(insights),
            "insights": insights,
            "memory_stats": {
                "total_memories": memory_metrics.get("memories_stored", 0),
                "patterns_learned": memory_metrics.get("patterns_learned", 0),
                "insights_generated": memory_metrics.get("insights_generated", 0)
            },
            "query_timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Memory query error: {str(e)}"
        )


@enhanced_router.post("/copilot/query")
async def analyst_copilot_query(
    request: AnalystCopilotRequest,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Query analyst copilot"""
    try:
        user_info = await verify_token(credentials.credentials)
        analyst_id = user_info.get("username", "unknown")

        # Create analyst query
        query = AnalystQuery(
            query_id=f"query_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            analyst_id=analyst_id,
            query_text=request.query,
            query_type=request.query_type or QueryType.INCIDENT_ANALYSIS,
            context=request.context,
            preferred_format=request.preferred_format,
            session_id=request.session_id
        )

        # Process query
        response = await analyst_copilot.process_analyst_query(query)

        return {
            "query_id": query.query_id,
            "response": {
                "text": response.response_text,
                "confidence": response.confidence,
                "recommendations": response.recommendations,
                "follow_up_questions": response.follow_up_questions,
                "supporting_evidence": response.supporting_evidence,
                "data_sources": response.data_sources
            },
            "processing_time": response.processing_time,
            "timestamp": response.timestamp.isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Copilot query error: {str(e)}"
        )


@enhanced_router.post("/copilot/session")
async def create_copilot_session(
    preferences: Dict[str, Any] = None,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Create new analyst copilot session"""
    try:
        user_info = await verify_token(credentials.credentials)
        analyst_id = user_info.get("username", "unknown")

        session_id = await analyst_copilot.create_analyst_session(
            analyst_id=analyst_id,
            preferences=preferences or {}
        )

        return {
            "session_id": session_id,
            "analyst_id": analyst_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Session creation error: {str(e)}"
        )


@enhanced_router.delete("/copilot/session/{session_id}")
async def end_copilot_session(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """End analyst copilot session"""
    try:
        await verify_token(credentials.credentials)

        await analyst_copilot.end_analyst_session(session_id)

        return {
            "session_id": session_id,
            "status": "ended",
            "ended_at": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Session end error: {str(e)}"
        )


@enhanced_router.get("/intelligence/system-status")
async def get_intelligence_system_status(
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Get comprehensive intelligence system status"""
    try:
        await verify_token(credentials.credentials)

        # Get individual agent metrics
        agents_status = {
            "behavioral_anomaly_detector": behavioral_anomaly_detector.get_metrics(),
            "network_anomaly_detector": network_anomaly_detector.get_metrics(),
            "threat_intelligence_engine": threat_intelligence_engine.get_metrics(),
            "incident_memory_system": incident_memory_system.get_metrics(),
            "analyst_copilot": analyst_copilot.get_metrics()
        }

        # Calculate overall intelligence health
        healthy_agents = sum(1 for metrics in agents_status.values()
                           if metrics.get("is_healthy", True))
        total_agents = len(agents_status)

        overall_health = "healthy"
        if healthy_agents < total_agents * 0.8:
            overall_health = "degraded"
        if healthy_agents < total_agents * 0.6:
            overall_health = "unhealthy"

        return {
            "overall_health": overall_health,
            "healthy_agents": healthy_agents,
            "total_agents": total_agents,
            "intelligence_metrics": {
                "total_events_processed": sum(
                    metrics.get("events_processed", 0) for metrics in agents_status.values()
                ),
                "anomalies_detected": sum([
                    agents_status["behavioral_anomaly_detector"].get("anomalies_detected", 0),
                    agents_status["network_anomaly_detector"].get("anomalies_detected", 0)
                ]),
                "memories_stored": agents_status["incident_memory_system"].get("memories_stored", 0),
                "copilot_queries": agents_status["analyst_copilot"].get("queries_processed", 0)
            },
            "agents_status": agents_status,
            "status_timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Status error: {str(e)}"
        )


@enhanced_router.get("/intelligence/performance")
async def get_intelligence_performance(
    credentials: HTTPAuthorizationCredentials = Depends(verify_token)
) -> Dict[str, Any]:
    """Get intelligence system performance metrics"""
    try:
        await verify_token(credentials.credentials)

        # Aggregate performance metrics
        performance_data = {
            "anomaly_detection": {
                "behavioral_events_processed": behavioral_anomaly_detector.get_metrics().get("events_processed", 0),
                "network_flows_processed": network_anomaly_detector.get_metrics().get("flows_processed", 0),
                "total_anomalies": (
                    behavioral_anomaly_detector.get_metrics().get("anomalies_detected", 0) +
                    network_anomaly_detector.get_metrics().get("anomalies_detected", 0)
                )
            },
            "threat_intelligence": {
                "enrichment_requests": threat_intelligence_engine.get_metrics().get("enrichment_requests", 0),
                "hit_rate": threat_intelligence_engine.get_metrics().get("hit_rate", 0.0),
                "api_errors": threat_intelligence_engine.get_metrics().get("api_errors", 0)
            },
            "memory_system": {
                "memories_stored": incident_memory_system.get_metrics().get("memories_stored", 0),
                "patterns_learned": incident_memory_system.get_metrics().get("patterns_learned", 0),
                "insights_generated": incident_memory_system.get_metrics().get("insights_generated", 0)
            },
            "analyst_copilot": {
                "queries_processed": analyst_copilot.get_metrics().get("queries_processed", 0),
                "active_sessions": analyst_copilot.get_metrics().get("active_sessions", 0),
                "avg_response_time": analyst_copilot.get_metrics().get("avg_response_time", 0.0)
            }
        }

        return {
            "performance_metrics": performance_data,
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
            "system_version": "SATRIA AI v2.0 - Intelligence Phase"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Performance metrics error: {str(e)}"
        )