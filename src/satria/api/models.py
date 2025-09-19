"""
SATRIA AI API Models
Pydantic models for API request/response schemas
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from enum import Enum

from satria.core.quantum_decision_engine import DecisionContext
from satria.integrations.pentestgpt_planner import PlanConstraints


class HealthStatus(BaseModel):
    """Health check response model"""
    status: str = Field(..., description="Health status: healthy, degraded, unhealthy")
    timestamp: datetime = Field(..., description="Check timestamp")
    version: Optional[str] = Field(None, description="Application version")
    environment: Optional[str] = Field(None, description="Environment name")
    uptime_seconds: Optional[int] = Field(None, description="Uptime in seconds")
    components: Optional[Dict[str, Any]] = Field(None, description="Component health status")


class EventIngestionResponse(BaseModel):
    """Event ingestion response"""
    event_id: str = Field(..., description="Event identifier")
    status: str = Field(..., description="Ingestion status")
    message: str = Field(..., description="Status message")


class BatchIngestionResponse(BaseModel):
    """Batch event ingestion response"""
    batch_id: str = Field(..., description="Batch identifier")
    event_count: int = Field(..., description="Number of events in batch")
    status: str = Field(..., description="Ingestion status")
    message: str = Field(..., description="Status message")


class RCAPathRequest(BaseModel):
    """RCA path finding request"""
    start_entity_id: str = Field(..., description="Starting entity ID")
    end_entity_id: str = Field(..., description="Target entity ID")
    max_hops: int = Field(default=6, ge=1, le=10, description="Maximum hops in path")


class RCAPathResponse(BaseModel):
    """RCA path finding response"""
    start_entity: str = Field(..., description="Starting entity ID")
    end_entity: str = Field(..., description="Target entity ID")
    path_count: int = Field(..., description="Number of paths found")
    paths: List[Dict[str, Any]] = Field(..., description="RCA paths")


class EntityTimelineResponse(BaseModel):
    """Entity timeline response"""
    entity_id: str = Field(..., description="Entity identifier")
    hours_back: int = Field(..., description="Time window in hours")
    event_count: int = Field(..., description="Number of events")
    timeline: List[Dict[str, Any]] = Field(..., description="Timeline events")


class QDEDecisionRequest(BaseModel):
    """QDE decision request"""
    context: DecisionContext = Field(..., description="Decision context")


class PersonaMixResponse(BaseModel):
    """Persona mix information"""
    elliot_weight: float = Field(..., description="Red team weight")
    mr_robot_weight: float = Field(..., description="Blue team weight")
    dominant_persona: str = Field(..., description="Dominant persona")
    confidence: float = Field(..., description="Decision confidence")
    reasoning: str = Field(..., description="Selection reasoning")


class ActionPlanResponse(BaseModel):
    """Action plan information"""
    plan_id: str = Field(..., description="Plan identifier")
    stage: str = Field(..., description="Response stage")
    priority: str = Field(..., description="Execution priority")
    actions: List[Dict[str, Any]] = Field(..., description="Actions to execute")
    approval_required: bool = Field(..., description="Whether approval is required")
    safety_score: float = Field(..., description="Safety score")
    estimated_duration: float = Field(..., description="Estimated duration in seconds")


class QDEDecisionResponse(BaseModel):
    """QDE decision response"""
    decision_id: str = Field(..., description="Decision identifier")
    persona_mix: PersonaMixResponse = Field(..., description="Persona mix")
    action_plan: ActionPlanResponse = Field(..., description="Action plan")
    reasoning: str = Field(..., description="Decision reasoning")
    guardrails_passed: bool = Field(..., description="Whether guardrails passed")
    timestamp: datetime = Field(..., description="Decision timestamp")


class ExecutionContext(BaseModel):
    """Red team execution context"""
    session_id: str = Field(..., description="Session identifier")
    user_id: str = Field(..., description="User identifier")
    target_scope: List[str] = Field(..., description="Target scope")
    time_budget_minutes: int = Field(..., description="Time budget in minutes")
    approval_status: str = Field(default="pending", description="Approval status")
    purpose: str = Field(default="purple_team_validation", description="Execution purpose")


class RedTeamExecutionRequest(BaseModel):
    """Red team tool execution request"""
    tool_name: str = Field(..., description="Tool name to execute")
    args: List[str] = Field(..., description="Tool arguments")
    context: ExecutionContext = Field(..., description="Execution context")


class RedTeamExecutionResponse(BaseModel):
    """Red team tool execution response"""
    execution_id: str = Field(..., description="Execution identifier")
    tool_name: str = Field(..., description="Tool name")
    command: str = Field(..., description="Full command executed")
    start_time: datetime = Field(..., description="Execution start time")
    end_time: Optional[datetime] = Field(None, description="Execution end time")
    exit_code: Optional[int] = Field(None, description="Exit code")
    stdout: str = Field(..., description="Standard output")
    stderr: str = Field(..., description="Standard error")
    artifacts: List[str] = Field(..., description="Generated artifacts")
    safety_violations: List[str] = Field(..., description="Safety violations")


class PurpleTeamSessionRequest(BaseModel):
    """Purple team session creation request"""
    scenario: str = Field(..., description="Exercise scenario")
    targets: List[str] = Field(..., description="Target systems")
    duration_hours: int = Field(default=2, ge=1, le=8, description="Session duration in hours")


class PurpleTeamSessionResponse(BaseModel):
    """Purple team session creation response"""
    session_id: str = Field(..., description="Session identifier")
    scenario: str = Field(..., description="Exercise scenario")
    targets: List[str] = Field(..., description="Target systems")
    duration_hours: int = Field(..., description="Session duration")
    status: str = Field(..., description="Session status")


class TargetProfile(BaseModel):
    """Target profile for penetration testing"""
    name: str = Field(..., description="Target name")
    type: str = Field(..., description="Target type")
    domain: Optional[str] = Field(None, description="Domain name")
    ip_addresses: List[str] = Field(default_factory=list, description="IP addresses")
    services: List[Dict[str, Any]] = Field(default_factory=list, description="Known services")
    technologies: List[str] = Field(default_factory=list, description="Technologies in use")
    business_criticality: str = Field(default="medium", description="Business criticality")
    data_classification: str = Field(default="internal", description="Data classification")


class PentestPlanRequest(BaseModel):
    """Penetration test plan creation request"""
    target_profile: TargetProfile = Field(..., description="Target profile")
    constraints: PlanConstraints = Field(..., description="Planning constraints")
    scenario: str = Field(default="general_assessment", description="Test scenario")


class PentestPlanResponse(BaseModel):
    """Penetration test plan creation response"""
    plan_id: str = Field(..., description="Plan identifier")
    name: str = Field(..., description="Plan name")
    description: str = Field(..., description="Plan description")
    task_count: int = Field(..., description="Number of tasks")
    estimated_duration: float = Field(..., description="Estimated duration in seconds")
    created_at: datetime = Field(..., description="Creation timestamp")
    status: str = Field(..., description="Plan status")
    approval_required: bool = Field(..., description="Whether approval is required")


class PlanApprovalResponse(BaseModel):
    """Plan approval response"""
    plan_id: str = Field(..., description="Plan identifier")
    status: str = Field(..., description="Approval status")
    approved_by: str = Field(..., description="Approver username")
    approved_at: datetime = Field(..., description="Approval timestamp")


class SystemMetricsResponse(BaseModel):
    """System metrics response"""
    event_bus: Dict[str, Any] = Field(..., description="Event bus metrics")
    qde: Dict[str, Any] = Field(..., description="QDE metrics")
    red_team_gateway: Dict[str, Any] = Field(..., description="Red team gateway metrics")
    pentestgpt_planner: Dict[str, Any] = Field(..., description="PentestGPT planner metrics")
    uptime_seconds: int = Field(..., description="System uptime in seconds")


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error message")
    timestamp: datetime = Field(..., description="Error timestamp")
    path: str = Field(..., description="Request path")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")


class APIKeyRequest(BaseModel):
    """API key creation request"""
    name: str = Field(..., description="API key name")
    permissions: List[str] = Field(..., description="Permissions")
    expires_in_days: Optional[int] = Field(None, description="Expiration in days")


class APIKeyResponse(BaseModel):
    """API key creation response"""
    key_id: str = Field(..., description="API key identifier")
    api_key: str = Field(..., description="API key (shown only once)")
    name: str = Field(..., description="API key name")
    permissions: List[str] = Field(..., description="Permissions")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class UserInfo(BaseModel):
    """User information"""
    username: str = Field(..., description="Username")
    roles: List[str] = Field(..., description="User roles")
    permissions: List[str] = Field(..., description="User permissions")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")


class AgentStatus(BaseModel):
    """Agent status information"""
    agent_id: str = Field(..., description="Agent identifier")
    agent_name: str = Field(..., description="Agent name")
    status: str = Field(..., description="Agent status")
    last_heartbeat: Optional[datetime] = Field(None, description="Last heartbeat")
    metrics: Dict[str, Any] = Field(..., description="Agent metrics")
    configuration: Dict[str, Any] = Field(..., description="Agent configuration")


class AgentRegistryResponse(BaseModel):
    """Agent registry response"""
    total_agents: int = Field(..., description="Total number of agents")
    online_agents: int = Field(..., description="Number of online agents")
    agents: List[AgentStatus] = Field(..., description="Agent status list")


class DetectionRuleRequest(BaseModel):
    """Detection rule creation/update request"""
    rule_name: str = Field(..., description="Rule name")
    rule_type: str = Field(..., description="Rule type (sigma, yara, custom)")
    rule_content: str = Field(..., description="Rule content")
    severity: str = Field(..., description="Rule severity")
    tags: List[str] = Field(default_factory=list, description="Rule tags")
    enabled: bool = Field(default=True, description="Whether rule is enabled")


class DetectionRuleResponse(BaseModel):
    """Detection rule response"""
    rule_id: str = Field(..., description="Rule identifier")
    rule_name: str = Field(..., description="Rule name")
    rule_type: str = Field(..., description="Rule type")
    severity: str = Field(..., description="Rule severity")
    enabled: bool = Field(..., description="Whether rule is enabled")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    performance_metrics: Optional[Dict[str, Any]] = Field(None, description="Rule performance metrics")


class PlaybookRequest(BaseModel):
    """Playbook execution request"""
    playbook_id: str = Field(..., description="Playbook identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Execution parameters")
    approval_required: bool = Field(default=True, description="Whether approval is required")
    dry_run: bool = Field(default=False, description="Whether to run in dry-run mode")


class PlaybookResponse(BaseModel):
    """Playbook execution response"""
    execution_id: str = Field(..., description="Execution identifier")
    playbook_id: str = Field(..., description="Playbook identifier")
    status: str = Field(..., description="Execution status")
    started_at: datetime = Field(..., description="Start timestamp")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    progress: float = Field(default=0.0, description="Execution progress (0.0-1.0)")


# Validators
@validator('status', allow_reuse=True)
def validate_status(cls, v):
    """Validate status fields"""
    valid_statuses = ['pending', 'running', 'completed', 'failed', 'cancelled']
    if v not in valid_statuses:
        raise ValueError(f'Status must be one of: {valid_statuses}')
    return v