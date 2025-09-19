"""
SATRIA AI Agent Orchestrator
Manages agent lifecycle, communication, and coordination
"""

import asyncio
import logging
import json
from typing import Any, Dict, List, Optional, Set, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import uuid

from satria.core.agent_base import BaseAgent, AgentConfig, AgentStatus
from satria.models.events import BaseEvent, EventBatch
from satria.core.event_bus import event_bus, subscribe_to_events
from satria.core.config import settings

# Phase 1 Agents
from satria.agents.perception.log_collector import log_collector
from satria.agents.perception.edr_connector import edr_connector
from satria.agents.context.risk_scorer import risk_scorer
from satria.agents.decision.triage_planner import triage_planner
from satria.agents.orchestration.edr_orchestrator import edr_orchestrator

# Phase 2 Intelligence Agents
from satria.agents.intelligence.behavioral_anomaly_detector import behavioral_anomaly_detector
from satria.agents.intelligence.network_anomaly_detector import network_anomaly_detector
from satria.agents.intelligence.threat_intelligence_engine import threat_intelligence_engine
from satria.agents.memory.incident_memory_system import incident_memory_system
from satria.agents.copilot.analyst_copilot import analyst_copilot


class OrchestratorState(str, Enum):
    """Orchestrator states"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class AgentRegistration:
    """Agent registration information"""
    agent_id: str
    agent_instance: BaseAgent
    config: AgentConfig
    status: AgentStatus
    last_heartbeat: datetime
    task_handle: Optional[asyncio.Task] = None
    restart_count: int = 0
    max_restarts: int = 5


@dataclass
class MessageRoute:
    """Message routing configuration"""
    source_pattern: str  # Event type pattern or agent ID
    destination_agents: List[str]  # Target agent IDs
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1-10, 10 highest


@dataclass
class WorkflowStep:
    """Workflow execution step"""
    step_id: str
    agent_id: str
    action: str
    parameters: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Workflow:
    """Agent coordination workflow"""
    workflow_id: str
    name: str
    description: str
    steps: List[WorkflowStep]
    created_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "pending"  # pending, running, completed, failed
    current_step: Optional[str] = None


class AgentOrchestrator:
    """
    Enhanced SATRIA Agent Orchestrator (Phase 2)

    Responsibilities:
    1. Agent lifecycle management (start, stop, restart)
    2. Inter-agent communication and message routing
    3. Workflow coordination and execution
    4. Health monitoring and failure recovery
    5. Load balancing and resource management
    6. Event distribution and agent coordination
    7. Advanced AI pipeline orchestration
    8. Intelligence layer coordination
    """

    def __init__(self):
        self.logger = logging.getLogger("satria.orchestrator")

        # Orchestrator state
        self.state = OrchestratorState.INITIALIZING
        self.start_time = datetime.utcnow()

        # Agent management organized by layers
        self.registered_agents: Dict[str, AgentRegistration] = {}
        self.agent_groups: Dict[str, Set[str]] = {}  # Group name -> agent IDs

        # Phase 2: Intelligence agents organized by capability
        self.core_agents = {
            "perception": [log_collector, edr_connector],
            "context": [risk_scorer],
            "intelligence": [behavioral_anomaly_detector, network_anomaly_detector, threat_intelligence_engine],
            "memory": [incident_memory_system],
            "decision": [triage_planner],
            "orchestration": [edr_orchestrator],
            "copilot": [analyst_copilot]
        }

        # Message routing
        self.message_routes: List[MessageRoute] = []
        self.event_subscriptions: Dict[str, List[str]] = {}  # Event type -> agent IDs

        # Workflow management
        self.workflows: Dict[str, Workflow] = {}
        self.active_workflows: Set[str] = set()

        # Performance metrics
        self.metrics = {
            "agents_started": 0,
            "agents_stopped": 0,
            "agents_restarted": 0,
            "messages_routed": 0,
            "workflows_executed": 0,
            "failures": 0,
            "pipeline_events_processed": 0,
            "intelligence_analyses": 0
        }

        # Configuration
        self.heartbeat_interval = 30  # seconds
        self.health_check_interval = 60  # seconds
        self.max_concurrent_workflows = 10
        self.enable_intelligent_routing = True

    async def initialize(self) -> bool:
        """Initialize the enhanced orchestrator"""
        try:
            self.logger.info("🚀 Initializing Enhanced Agent Orchestrator (Phase 2)")

            # Initialize core agents in order
            await self._initialize_core_agents()

            # Setup enhanced message routes
            await self._setup_enhanced_routes()

            # Setup agent groups
            await self._setup_agent_groups()

            # Start orchestrator tasks
            await self._start_orchestrator_tasks()

            # Subscribe to Event Bus
            await self._setup_event_subscriptions()

            # Start intelligent event processing pipeline
            await self._start_intelligent_pipeline()

            self.state = OrchestratorState.RUNNING
            self.logger.info("🎯 Enhanced Agent Orchestrator initialized successfully!")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize enhanced orchestrator: {e}")
            self.state = OrchestratorState.ERROR
            return False

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and all agents"""
        self.logger.info("Shutting down Agent Orchestrator")
        self.state = OrchestratorState.STOPPING

        try:
            # Stop all active workflows
            await self._stop_all_workflows()

            # Stop all agents
            await self._stop_all_agents()

            # Cancel orchestrator tasks
            await self._stop_orchestrator_tasks()

            self.state = OrchestratorState.STOPPED
            self.logger.info("Agent Orchestrator shutdown completed")

        except Exception as e:
            self.logger.error(f"Error during orchestrator shutdown: {e}")
            self.state = OrchestratorState.ERROR

    async def register_agent(self, agent: BaseAgent) -> bool:
        """Register new agent with orchestrator"""
        try:
            agent_id = agent.agent_id

            if agent_id in self.registered_agents:
                self.logger.warning(f"Agent {agent_id} already registered")
                return False

            # Create registration
            registration = AgentRegistration(
                agent_id=agent_id,
                agent_instance=agent,
                config=agent.config,
                status=agent.get_status(),
                last_heartbeat=datetime.utcnow()
            )

            self.registered_agents[agent_id] = registration

            # Start agent
            success = await self._start_agent(registration)

            if success:
                self.logger.info(f"Successfully registered agent: {agent_id}")
                self.metrics["agents_started"] += 1

                # Add to appropriate groups
                await self._assign_agent_to_groups(agent)

                # Setup event subscriptions for agent
                await self._setup_agent_subscriptions(agent)

            return success

        except Exception as e:
            self.logger.error(f"Error registering agent {agent.agent_id}: {e}")
            return False

    async def unregister_agent(self, agent_id: str) -> bool:
        """Unregister agent from orchestrator"""
        try:
            if agent_id not in self.registered_agents:
                self.logger.warning(f"Agent {agent_id} not registered")
                return False

            registration = self.registered_agents[agent_id]

            # Stop agent
            await self._stop_agent(registration)

            # Remove from groups
            await self._remove_agent_from_groups(agent_id)

            # Remove registration
            del self.registered_agents[agent_id]

            self.logger.info(f"Successfully unregistered agent: {agent_id}")
            self.metrics["agents_stopped"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Error unregistering agent {agent_id}: {e}")
            return False

    async def _start_agent(self, registration: AgentRegistration) -> bool:
        """Start individual agent"""
        try:
            agent = registration.agent_instance

            # Start agent in background task
            task = asyncio.create_task(agent.start())
            registration.task_handle = task

            # Wait briefly to check if agent started successfully
            await asyncio.sleep(0.1)

            if task.done():
                # Check if agent failed to start
                try:
                    await task
                except Exception as e:
                    self.logger.error(f"Agent {registration.agent_id} failed to start: {e}")
                    return False

            registration.status = agent.get_status()
            registration.last_heartbeat = datetime.utcnow()

            return True

        except Exception as e:
            self.logger.error(f"Error starting agent {registration.agent_id}: {e}")
            return False

    async def _stop_agent(self, registration: AgentRegistration) -> None:
        """Stop individual agent"""
        try:
            agent = registration.agent_instance

            # Stop agent gracefully
            await agent.stop()

            # Cancel task if still running
            if registration.task_handle and not registration.task_handle.done():
                registration.task_handle.cancel()
                try:
                    await registration.task_handle
                except asyncio.CancelledError:
                    pass

            registration.task_handle = None

        except Exception as e:
            self.logger.error(f"Error stopping agent {registration.agent_id}: {e}")

    async def send_message_to_agent(self, agent_id: str, event: BaseEvent) -> bool:
        """Send message to specific agent"""
        try:
            if agent_id not in self.registered_agents:
                self.logger.warning(f"Agent {agent_id} not found for message routing")
                return False

            registration = self.registered_agents[agent_id]
            agent = registration.agent_instance

            # Add message to agent's input queue
            await agent.add_event(event)

            self.metrics["messages_routed"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Error sending message to agent {agent_id}: {e}")
            return False

    async def broadcast_to_group(self, group_name: str, event: BaseEvent) -> int:
        """Broadcast message to all agents in group"""
        try:
            if group_name not in self.agent_groups:
                self.logger.warning(f"Agent group {group_name} not found")
                return 0

            agent_ids = self.agent_groups[group_name]
            success_count = 0

            for agent_id in agent_ids:
                if await self.send_message_to_agent(agent_id, event):
                    success_count += 1

            return success_count

        except Exception as e:
            self.logger.error(f"Error broadcasting to group {group_name}: {e}")
            return 0

    async def route_event(self, event: BaseEvent) -> None:
        """Route event based on configured rules"""
        try:
            destinations = set()

            # Apply routing rules
            for route in self.message_routes:
                if await self._matches_route(event, route):
                    destinations.update(route.destination_agents)

            # Check explicit destinations in event
            if event.destinations:
                destinations.update(event.destinations)

            # Route to destinations
            for agent_id in destinations:
                await self.send_message_to_agent(agent_id, event)

        except Exception as e:
            self.logger.error(f"Error routing event {event.event_id}: {e}")

    async def _matches_route(self, event: BaseEvent, route: MessageRoute) -> bool:
        """Check if event matches routing rule"""
        try:
            # Check source pattern
            if route.source_pattern != "*":
                if not (event.event_type == route.source_pattern or
                       event.source_agent == route.source_pattern):
                    return False

            # Check conditions
            for condition_key, condition_value in route.conditions.items():
                if hasattr(event, condition_key):
                    event_value = getattr(event, condition_key)
                    if event_value != condition_value:
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking route match: {e}")
            return False

    async def execute_workflow(self, workflow: Workflow) -> bool:
        """Execute agent coordination workflow"""
        try:
            if len(self.active_workflows) >= self.max_concurrent_workflows:
                self.logger.warning("Maximum concurrent workflows reached")
                return False

            workflow_id = workflow.workflow_id
            self.workflows[workflow_id] = workflow
            self.active_workflows.add(workflow_id)

            workflow.status = "running"

            self.logger.info(f"Starting workflow: {workflow_id}")

            # Execute workflow steps
            success = await self._execute_workflow_steps(workflow)

            if success:
                workflow.status = "completed"
                self.logger.info(f"Workflow {workflow_id} completed successfully")
            else:
                workflow.status = "failed"
                self.logger.error(f"Workflow {workflow_id} failed")

            self.active_workflows.discard(workflow_id)
            self.metrics["workflows_executed"] += 1

            return success

        except Exception as e:
            self.logger.error(f"Error executing workflow {workflow.workflow_id}: {e}")
            workflow.status = "failed"
            self.active_workflows.discard(workflow.workflow_id)
            return False

    async def _execute_workflow_steps(self, workflow: Workflow) -> bool:
        """Execute individual workflow steps"""
        try:
            completed_steps = set()

            while len(completed_steps) < len(workflow.steps):
                # Find ready steps (dependencies satisfied)
                ready_steps = [
                    step for step in workflow.steps
                    if step.step_id not in completed_steps
                    and all(dep in completed_steps for dep in step.dependencies)
                ]

                if not ready_steps:
                    self.logger.error(f"Workflow {workflow.workflow_id} has circular dependencies or no ready steps")
                    return False

                # Execute ready steps concurrently
                step_tasks = []
                for step in ready_steps:
                    task = asyncio.create_task(self._execute_workflow_step(step))
                    step_tasks.append((step, task))

                # Wait for step completion
                for step, task in step_tasks:
                    try:
                        success = await task
                        if success:
                            completed_steps.add(step.step_id)
                            workflow.current_step = step.step_id
                        else:
                            self.logger.error(f"Workflow step {step.step_id} failed")
                            return False
                    except Exception as e:
                        self.logger.error(f"Error in workflow step {step.step_id}: {e}")
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Error executing workflow steps: {e}")
            return False

    async def _execute_workflow_step(self, step: WorkflowStep) -> bool:
        """Execute single workflow step"""
        try:
            agent_id = step.agent_id

            if agent_id not in self.registered_agents:
                self.logger.error(f"Agent {agent_id} not found for workflow step {step.step_id}")
                return False

            registration = self.registered_agents[agent_id]
            agent = registration.agent_instance

            # Create action event
            action_event = BaseEvent(
                event_type="workflow_action",
                event_category="system_activity",
                event_class="process_activity",
                source_agent="orchestrator",
                enrichment={
                    "workflow_step_id": step.step_id,
                    "action": step.action,
                    "parameters": step.parameters
                }
            )

            # Send to agent
            success = await self.send_message_to_agent(agent_id, action_event)

            if success:
                self.logger.debug(f"Workflow step {step.step_id} sent to agent {agent_id}")

            return success

        except Exception as e:
            self.logger.error(f"Error executing workflow step {step.step_id}: {e}")
            return False

    async def _setup_default_routes(self) -> None:
        """Setup default message routing rules"""
        default_routes = [
            # Log events to Context agents
            MessageRoute(
                source_pattern="log_collector",
                destination_agents=["entity_resolution", "temporal_reasoning", "risk_scoring"]
            ),
            # EDR events to Analysis agents
            MessageRoute(
                source_pattern="edr_connector",
                destination_agents=["anomaly_detector", "mitre_mapper", "context_graph"]
            ),
            # High-risk events to QDE
            MessageRoute(
                source_pattern="*",
                destination_agents=["qde"],
                conditions={"risk_score": ">= 80"}
            ),
            # Detection findings to Response agents
            MessageRoute(
                source_pattern="*",
                destination_agents=["triage_planner", "playbook_selector"],
                conditions={"event_category": "findings"}
            )
        ]

        self.message_routes.extend(default_routes)

    async def _setup_agent_groups(self) -> None:
        """Setup agent groups for broadcast messaging"""
        self.agent_groups = {
            "perception": set(),
            "context": set(),
            "memory": set(),
            "decision": set(),
            "action": set(),
            "governance": set(),
            "communication": set(),
            "detectors": set(),
            "orchestrators": set()
        }

    async def _assign_agent_to_groups(self, agent: BaseAgent) -> None:
        """Assign agent to appropriate groups based on type"""
        agent_type = agent.config.agent_type.lower()
        agent_id = agent.agent_id

        # Map agent types to groups
        type_group_mapping = {
            "perception": ["perception"],
            "context": ["context"],
            "memory": ["memory"],
            "decision": ["decision"],
            "action": ["action"],
            "governance": ["governance"],
            "communication": ["communication"]
        }

        # Special mappings for specific agents
        if "detector" in agent.agent_name.lower():
            self.agent_groups["detectors"].add(agent_id)

        if "orchestrator" in agent.agent_name.lower():
            self.agent_groups["orchestrators"].add(agent_id)

        # Add to type-based groups
        groups = type_group_mapping.get(agent_type, [])
        for group in groups:
            if group in self.agent_groups:
                self.agent_groups[group].add(agent_id)

    async def _remove_agent_from_groups(self, agent_id: str) -> None:
        """Remove agent from all groups"""
        for group_agents in self.agent_groups.values():
            group_agents.discard(agent_id)

    async def _setup_agent_subscriptions(self, agent: BaseAgent) -> None:
        """Setup event subscriptions for agent"""
        # This would be expanded based on agent capabilities
        # For now, simplified implementation
        pass

    async def _start_orchestrator_tasks(self) -> None:
        """Start background orchestrator tasks"""
        # Health monitoring task
        asyncio.create_task(self._health_monitoring_loop())

        # Agent heartbeat checking task
        asyncio.create_task(self._heartbeat_monitoring_loop())

        # Metrics collection task
        asyncio.create_task(self._metrics_collection_loop())

    async def _stop_orchestrator_tasks(self) -> None:
        """Stop background orchestrator tasks"""
        # Tasks will be cancelled when orchestrator stops
        pass

    async def _health_monitoring_loop(self) -> None:
        """Monitor agent health and restart failed agents"""
        while self.state == OrchestratorState.RUNNING:
            try:
                for agent_id, registration in self.registered_agents.items():
                    await self._check_agent_health(registration)

                await asyncio.sleep(self.health_check_interval)

            except Exception as e:
                self.logger.error(f"Error in health monitoring: {e}")
                await asyncio.sleep(5)

    async def _heartbeat_monitoring_loop(self) -> None:
        """Monitor agent heartbeats"""
        while self.state == OrchestratorState.RUNNING:
            try:
                current_time = datetime.utcnow()
                heartbeat_timeout = timedelta(seconds=self.heartbeat_interval * 3)

                for agent_id, registration in self.registered_agents.items():
                    if current_time - registration.last_heartbeat > heartbeat_timeout:
                        self.logger.warning(f"Agent {agent_id} heartbeat timeout")
                        await self._handle_agent_failure(registration)

                await asyncio.sleep(self.heartbeat_interval)

            except Exception as e:
                self.logger.error(f"Error in heartbeat monitoring: {e}")
                await asyncio.sleep(5)

    async def _metrics_collection_loop(self) -> None:
        """Collect metrics from agents"""
        while self.state == OrchestratorState.RUNNING:
            try:
                # Collect agent metrics
                for registration in self.registered_agents.values():
                    registration.status = registration.agent_instance.get_status()

                await asyncio.sleep(60)  # Collect every minute

            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(5)

    async def _check_agent_health(self, registration: AgentRegistration) -> None:
        """Check individual agent health"""
        try:
            agent = registration.agent_instance

            # Check if agent task is still running
            if registration.task_handle and registration.task_handle.done():
                self.logger.warning(f"Agent {registration.agent_id} task completed unexpectedly")
                await self._handle_agent_failure(registration)

        except Exception as e:
            self.logger.error(f"Error checking agent health {registration.agent_id}: {e}")

    async def _handle_agent_failure(self, registration: AgentRegistration) -> None:
        """Handle agent failure with restart logic"""
        try:
            agent_id = registration.agent_id

            if registration.restart_count >= registration.max_restarts:
                self.logger.error(f"Agent {agent_id} exceeded max restarts, giving up")
                self.metrics["failures"] += 1
                return

            self.logger.info(f"Attempting to restart agent {agent_id}")

            # Stop current agent instance
            await self._stop_agent(registration)

            # Wait briefly before restart
            await asyncio.sleep(5)

            # Restart agent
            success = await self._start_agent(registration)

            if success:
                registration.restart_count += 1
                registration.last_heartbeat = datetime.utcnow()
                self.metrics["agents_restarted"] += 1
                self.logger.info(f"Successfully restarted agent {agent_id}")
            else:
                self.logger.error(f"Failed to restart agent {agent_id}")
                self.metrics["failures"] += 1

        except Exception as e:
            self.logger.error(f"Error handling agent failure {registration.agent_id}: {e}")

    async def _setup_event_subscriptions(self) -> None:
        """Setup Event Bus subscriptions for orchestrator"""
        # Subscribe to all events for routing
        subscribe_to_events("*", self.route_event)

    async def _stop_all_workflows(self) -> None:
        """Stop all active workflows"""
        for workflow_id in list(self.active_workflows):
            workflow = self.workflows.get(workflow_id)
            if workflow:
                workflow.status = "cancelled"
            self.active_workflows.discard(workflow_id)

    async def _stop_all_agents(self) -> None:
        """Stop all registered agents"""
        for registration in list(self.registered_agents.values()):
            await self._stop_agent(registration)

    def get_agent_status(self, agent_id: str) -> Optional[AgentStatus]:
        """Get status of specific agent"""
        registration = self.registered_agents.get(agent_id)
        if registration:
            return registration.status
        return None

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all registered agents"""
        return [
            {
                "agent_id": reg.agent_id,
                "agent_name": reg.agent_instance.agent_name,
                "agent_type": reg.config.agent_type,
                "status": reg.status.status,
                "last_heartbeat": reg.last_heartbeat.isoformat(),
                "restart_count": reg.restart_count,
                "uptime_seconds": reg.status.metrics.uptime_seconds
            }
            for reg in self.registered_agents.values()
        ]

    def get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get orchestrator performance metrics"""
        return {
            **self.metrics,
            "state": self.state.value,
            "registered_agents": len(self.registered_agents),
            "active_workflows": len(self.active_workflows),
            "agent_groups": {name: len(agents) for name, agents in self.agent_groups.items()},
            "uptime_seconds": int((datetime.utcnow() - self.start_time).total_seconds())
        }


# Global orchestrator instance
agent_orchestrator = AgentOrchestrator()