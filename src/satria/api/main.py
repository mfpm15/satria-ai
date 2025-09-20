"""
SATRIA AI FastAPI Application
Main API server for SATRIA AI cybersecurity platform
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import uvicorn

from satria.core.config import settings
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.core.quantum_decision_engine import qde
from satria.integrations.red_team_gateway import red_team_gateway
from satria.integrations.pentestgpt_planner import pentestgpt_planner
from satria.models.events import BaseEvent, EventBatch
from satria.api.models import *
from satria.api.security import verify_token
from satria.api.enhanced_endpoints import enhanced_router


# Global state for services
class SATRIAServices:
    def __init__(self):
        self.initialized = False
        self.start_time = datetime.utcnow()
        self.agent_registry = {}

    async def initialize(self):
        """Initialize all SATRIA services"""
        if self.initialized:
            return

        try:
            # Initialize Event Bus (optional)
            try:
                await event_bus.initialize()
                logging.info("Event Bus initialized successfully")
            except Exception as e:
                logging.warning(f"Failed to initialize Event Bus: {e}")

            # Initialize Context Graph (optional)
            try:
                await context_graph.initialize()
                logging.info("Context Graph initialized successfully")
            except Exception as e:
                logging.warning(f"Failed to initialize Context Graph: {e}")

            # Setup Red Team Gateway
            # red_team_gateway is already initialized

            # Initialize PentestGPT Planner
            # pentestgpt_planner is already initialized

            self.initialized = True
            logging.info("SATRIA services initialized successfully")

        except Exception as e:
            logging.error(f"Failed to initialize SATRIA services: {e}")
            # Don't raise - allow app to start with degraded functionality

    async def shutdown(self):
        """Shutdown all SATRIA services"""
        try:
            await event_bus.shutdown()
            await context_graph.close()
            logging.info("SATRIA services shutdown completed")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")


# Global services instance
satria_services = SATRIAServices()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    await satria_services.initialize()
    yield
    # Shutdown
    await satria_services.shutdown()


# Create FastAPI application
app = FastAPI(
    title="SATRIA AI API v2.0",
    description="Smart Autonomous Threat Response & Intelligence Agent - Phase 2: Intelligence",
    version="2.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://satria.local"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include enhanced endpoints
app.include_router(enhanced_router)

# Security
security = HTTPBearer()


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """Root endpoint with API information"""
    return {
        "name": "SATRIA AI API v2.0",
        "version": "2.0.0",
        "description": "Smart Autonomous Threat Response & Intelligence Agent",
        "phase": "Phase 4: Enterprise Edition",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "api": "/api/v1/",
            "enterprise": "/api/v1/enterprise/"
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# Health check endpoints
@app.get("/health", tags=["Health"], status_code=200)
async def health_check() -> Dict[str, Any]:
    """Basic health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0",
        "environment": settings.environment
    }


@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check() -> Dict[str, Any]:
    """Detailed health check with component status"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": int((datetime.utcnow() - satria_services.start_time).total_seconds()),
        "components": {}
    }

    # Check Event Bus
    try:
        event_bus_metrics = event_bus.get_metrics()
        health_status["components"]["event_bus"] = {
            "status": "healthy",
            "metrics": event_bus_metrics
        }
    except Exception as e:
        health_status["components"]["event_bus"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"

    # Check Context Graph
    try:
        # Simple connectivity test
        health_status["components"]["context_graph"] = {
            "status": "healthy" if context_graph.driver else "unhealthy"
        }
    except Exception as e:
        health_status["components"]["context_graph"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"

    # Check QDE
    try:
        qde_metrics = qde.get_metrics()
        health_status["components"]["qde"] = {
            "status": "healthy",
            "metrics": qde_metrics
        }
    except Exception as e:
        health_status["components"]["qde"] = {
            "status": "unhealthy",
            "error": str(e)
        }

    # Check Red Team Gateway
    try:
        gateway_metrics = red_team_gateway.get_metrics()
        health_status["components"]["red_team_gateway"] = {
            "status": "healthy",
            "metrics": gateway_metrics
        }
    except Exception as e:
        health_status["components"]["red_team_gateway"] = {
            "status": "unhealthy",
            "error": str(e)
        }

    return health_status


@app.get("/ready", tags=["Health"])
async def readiness_check() -> Dict[str, Any]:
    """Kubernetes readiness check"""
    if not satria_services.initialized:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Services not yet initialized"
        )

    return {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat()
    }


# Event ingestion endpoints
@app.post("/v1/events", tags=["Events"])
async def ingest_event(
    event: BaseEvent,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, str]:
    """Ingest single event into SATRIA"""
    # Verify authentication
    user_info = await verify_token(credentials.credentials)

    # Add source metadata
    event.enrichment["api_ingestion"] = {
        "user": user_info.get("username", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
        "source": "api"
    }

    # Publish to Event Bus
    background_tasks.add_task(event_bus.publish, event)

    return {
        "event_id": event.event_id,
        "status": "accepted",
        "message": "Event queued for processing"
    }


@app.post("/v1/events/batch", tags=["Events"])
async def ingest_event_batch(
    batch: EventBatch,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Ingest batch of events into SATRIA"""
    # Verify authentication
    user_info = await verify_token(credentials.credentials)

    # Add source metadata to each event
    for event in batch.events:
        event.enrichment["api_ingestion"] = {
            "user": user_info.get("username", "unknown"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "api",
            "batch_id": batch.batch_id
        }

    # Publish to Event Bus
    background_tasks.add_task(event_bus.publish, batch)

    return {
        "batch_id": batch.batch_id,
        "event_count": len(batch.events),
        "status": "accepted",
        "message": f"Batch with {len(batch.events)} events queued for processing"
    }


# Context Graph endpoints
@app.post("/v1/graph/paths", tags=["Context Graph"])
async def find_rca_paths(
    request: RCAPathRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Find RCA paths between entities"""
    await verify_token(credentials.credentials)

    try:
        paths = await context_graph.find_rca_paths(
            request.start_entity_id,
            request.end_entity_id,
            request.max_hops
        )

        return {
            "start_entity": request.start_entity_id,
            "end_entity": request.end_entity_id,
            "path_count": len(paths),
            "paths": [path.to_dict() for path in paths]
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error finding RCA paths: {str(e)}"
        )


@app.get("/v1/graph/entity/{entity_id}/timeline", tags=["Context Graph"])
async def get_entity_timeline(
    entity_id: str,
    hours_back: int = 24,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get timeline of events for entity"""
    await verify_token(credentials.credentials)

    try:
        timeline = await context_graph.get_entity_timeline(entity_id, hours_back)

        return {
            "entity_id": entity_id,
            "hours_back": hours_back,
            "event_count": len(timeline),
            "timeline": timeline
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving timeline: {str(e)}"
        )


# QDE endpoints
@app.post("/v1/qde/decide", tags=["Decision Engine"])
async def qde_decision(
    request: QDEDecisionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Make decision using Quantum Decision Engine"""
    await verify_token(credentials.credentials)

    try:
        decision = await qde.decide(request.context)

        return {
            "decision_id": decision.decision_id,
            "persona_mix": {
                "elliot_weight": decision.persona_mix.elliot_weight,
                "mr_robot_weight": decision.persona_mix.mr_robot_weight,
                "dominant_persona": decision.persona_mix.dominant_persona.value,
                "confidence": decision.persona_mix.confidence,
                "reasoning": decision.persona_mix.reasoning
            },
            "action_plan": {
                "plan_id": decision.action_plan.plan_id,
                "stage": decision.action_plan.stage.value,
                "priority": decision.action_plan.priority.value,
                "actions": decision.action_plan.actions,
                "approval_required": decision.action_plan.approval_required,
                "safety_score": decision.action_plan.safety_score,
                "estimated_duration": decision.action_plan.estimated_duration.total_seconds()
            },
            "reasoning": decision.reasoning,
            "guardrails_passed": decision.guardrails_passed,
            "timestamp": decision.timestamp.isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDE decision error: {str(e)}"
        )


@app.get("/v1/qde/metrics", tags=["Decision Engine"])
async def qde_metrics(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get QDE performance metrics"""
    await verify_token(credentials.credentials)

    try:
        metrics = qde.get_metrics()
        return metrics

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving QDE metrics: {str(e)}"
        )


# Red Team Gateway endpoints
@app.post("/v1/red-team/execute", tags=["Red Team"])
async def execute_red_team_tool(
    request: RedTeamExecutionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Execute red team tool via HexStrike gateway"""
    user_info = await verify_token(credentials.credentials)

    # Check permissions
    if "red_team" not in user_info.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Red team permissions required"
        )

    try:
        execution = await red_team_gateway.execute_tool(
            request.tool_name,
            request.args,
            request.context
        )

        return {
            "execution_id": execution.execution_id,
            "tool_name": execution.tool_name,
            "command": execution.command,
            "start_time": execution.start_time.isoformat(),
            "end_time": execution.end_time.isoformat() if execution.end_time else None,
            "exit_code": execution.exit_code,
            "stdout": execution.stdout,
            "stderr": execution.stderr,
            "artifacts": execution.artifacts,
            "safety_violations": execution.safety_violations
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Red team execution error: {str(e)}"
        )


@app.post("/v1/red-team/session", tags=["Red Team"])
async def create_purple_team_session(
    request: PurpleTeamSessionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Create purple team session"""
    user_info = await verify_token(credentials.credentials)

    if "purple_team" not in user_info.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Purple team permissions required"
        )

    try:
        session_id = await red_team_gateway.create_purple_team_session(
            request.scenario,
            request.targets,
            request.duration_hours
        )

        return {
            "session_id": session_id,
            "scenario": request.scenario,
            "targets": request.targets,
            "duration_hours": request.duration_hours,
            "status": "created"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Session creation error: {str(e)}"
        )


# PentestGPT Planner endpoints
@app.post("/v1/planner/create-plan", tags=["AI Planner"])
async def create_pentest_plan(
    request: PentestPlanRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Create penetration test plan using PentestGPT"""
    user_info = await verify_token(credentials.credentials)

    if "planner" not in user_info.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Planner permissions required"
        )

    try:
        plan = await pentestgpt_planner.create_plan(
            request.target_profile,
            request.constraints,
            request.scenario
        )

        return {
            "plan_id": plan.plan_id,
            "name": plan.name,
            "description": plan.description,
            "task_count": len(plan.tasks),
            "estimated_duration": plan.estimated_total_duration.total_seconds(),
            "created_at": plan.created_at.isoformat(),
            "status": "created",
            "approval_required": any(task.priority.value in ["critical", "high"] for task in plan.tasks)
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Plan creation error: {str(e)}"
        )


@app.post("/v1/planner/approve-plan/{plan_id}", tags=["AI Planner"])
async def approve_pentest_plan(
    plan_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Approve penetration test plan"""
    user_info = await verify_token(credentials.credentials)

    if "planner_approver" not in user_info.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Plan approval permissions required"
        )

    try:
        approved = await pentestgpt_planner.approve_plan(
            plan_id,
            user_info.get("username", "unknown")
        )

        if approved:
            return {
                "plan_id": plan_id,
                "status": "approved",
                "approved_by": user_info.get("username"),
                "approved_at": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Plan not found"
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Plan approval error: {str(e)}"
        )


# Metrics and monitoring endpoints
@app.get("/v1/metrics", tags=["Monitoring"])
async def get_system_metrics(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get system-wide metrics"""
    await verify_token(credentials.credentials)

    try:
        metrics = {
            "event_bus": event_bus.get_metrics(),
            "qde": qde.get_metrics(),
            "red_team_gateway": red_team_gateway.get_metrics(),
            "pentestgpt_planner": pentestgpt_planner.get_metrics(),
            "uptime_seconds": int((datetime.utcnow() - satria_services.start_time).total_seconds())
        }

        return metrics

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving metrics: {str(e)}"
        )


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logging.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )


if __name__ == "__main__":
    uvicorn.run(
        "satria.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="info"
    )