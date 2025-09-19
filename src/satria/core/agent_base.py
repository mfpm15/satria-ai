"""
SATRIA AI Agent Base Classes
Base functionality for all SATRIA agents
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type, Union
from datetime import datetime
from pydantic import BaseModel
import uuid

from satria.models.events import BaseEvent, EventBatch
from satria.core.config import settings


class AgentConfig(BaseModel):
    """Agent Configuration"""
    agent_id: str
    agent_name: str
    agent_type: str
    version: str = "1.0.0"
    enabled: bool = True
    log_level: str = "INFO"
    heartbeat_interval: int = 30
    max_concurrent_tasks: int = 10
    retry_attempts: int = 3
    timeout_seconds: int = 300
    config: Dict[str, Any] = {}


class AgentMetrics(BaseModel):
    """Agent Performance Metrics"""
    events_processed: int = 0
    events_generated: int = 0
    processing_time_avg: float = 0.0
    errors_count: int = 0
    last_heartbeat: Optional[datetime] = None
    uptime_seconds: int = 0
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0


class AgentStatus(BaseModel):
    """Agent Status Information"""
    agent_id: str
    status: str  # "running", "stopped", "error", "initializing"
    last_update: datetime
    metrics: AgentMetrics
    config: AgentConfig
    error_message: Optional[str] = None


class BaseAgent(ABC):
    """Base class for all SATRIA AI agents"""

    def __init__(self, config=None, *, name=None, description=None, version=None):
        # Support both new AgentConfig interface and legacy (name, description, version) interface
        if config is not None:
            # New interface with AgentConfig
            self.config = config
            self.agent_id = config.agent_id
            self.agent_name = config.agent_name
            self.logger = logging.getLogger(f"satria.agents.{self.agent_name}")
            self.logger.setLevel(getattr(logging, config.log_level))
        elif name is not None:
            # Legacy interface with individual parameters
            self.config = AgentConfig(
                agent_id=str(uuid.uuid4()),
                agent_name=name,
                agent_type="legacy",
                version=version or "1.0.0"
            )
            self.agent_id = self.config.agent_id
            self.agent_name = name
            self.logger = logging.getLogger(f"satria.agents.{name}")
            self.logger.setLevel(logging.INFO)
        else:
            raise ValueError("Either config or name must be provided")

        # Initialize metrics
        self.metrics = AgentMetrics()
        self.status = "initializing"
        self.start_time = datetime.utcnow()

        # Task management
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.shutdown_event = asyncio.Event()

        # Event queues
        self.input_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.output_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the agent. Return True if successful."""
        pass

    @abstractmethod
    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process a single event. Return list of generated events."""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources before shutdown."""
        pass

    async def start(self) -> None:
        """Start the agent"""
        try:
            self.logger.info(f"Starting agent {self.agent_name}")

            # Initialize agent
            if not await self.initialize():
                raise Exception("Agent initialization failed")

            self.status = "running"
            self.logger.info(f"Agent {self.agent_name} started successfully")

            # Start main processing loop
            await self._main_loop()

        except Exception as e:
            self.status = "error"
            self.logger.error(f"Agent {self.agent_name} failed to start: {e}")
            raise

    async def stop(self) -> None:
        """Stop the agent gracefully"""
        self.logger.info(f"Stopping agent {self.agent_name}")

        # Signal shutdown
        self.shutdown_event.set()

        # Wait for running tasks to complete
        if self.running_tasks:
            self.logger.info(f"Waiting for {len(self.running_tasks)} tasks to complete")
            await asyncio.gather(*self.running_tasks.values(), return_exceptions=True)

        # Cleanup resources
        await self.cleanup()

        self.status = "stopped"
        self.logger.info(f"Agent {self.agent_name} stopped")

    async def _main_loop(self) -> None:
        """Main processing loop"""
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        processing_task = asyncio.create_task(self._processing_loop())

        try:
            # Wait for either shutdown or error
            done, pending = await asyncio.wait(
                [heartbeat_task, processing_task, self._wait_for_shutdown()],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()

        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
            self.status = "error"
        finally:
            # Ensure tasks are cancelled
            heartbeat_task.cancel()
            processing_task.cancel()

    async def _processing_loop(self) -> None:
        """Process events from input queue"""
        while not self.shutdown_event.is_set():
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(
                    self.input_queue.get(),
                    timeout=1.0
                )

                # Process event in separate task if concurrency allows
                if len(self.running_tasks) < self.config.max_concurrent_tasks:
                    task_id = str(uuid.uuid4())
                    task = asyncio.create_task(self._process_event_with_error_handling(event))
                    self.running_tasks[task_id] = task

                    # Schedule task cleanup
                    task.add_done_callback(lambda t: self.running_tasks.pop(task_id, None))
                else:
                    # Process synchronously if at capacity
                    await self._process_event_with_error_handling(event)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in processing loop: {e}")
                self.metrics.errors_count += 1

    async def _process_event_with_error_handling(self, event: BaseEvent) -> None:
        """Process event with error handling and metrics"""
        start_time = datetime.utcnow()

        try:
            # Process the event
            result_events = await self.process_event(event)

            # Update metrics
            self.metrics.events_processed += 1
            if result_events:
                self.metrics.events_generated += len(result_events)

                # Send generated events to output queue
                for result_event in result_events:
                    await self.output_queue.put(result_event)

            # Update processing time average
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.metrics.processing_time_avg = (
                (self.metrics.processing_time_avg * (self.metrics.events_processed - 1) + processing_time)
                / self.metrics.events_processed
            )

        except Exception as e:
            self.logger.error(f"Error processing event {event.event_id}: {e}")
            self.metrics.errors_count += 1

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats"""
        while not self.shutdown_event.is_set():
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.config.heartbeat_interval)
            except Exception as e:
                self.logger.error(f"Error in heartbeat loop: {e}")

    async def _send_heartbeat(self) -> None:
        """Send heartbeat with current status"""
        self.metrics.last_heartbeat = datetime.utcnow()
        self.metrics.uptime_seconds = int((datetime.utcnow() - self.start_time).total_seconds())

        # Here you would send the heartbeat to the orchestrator
        # For now, just log debug message
        self.logger.debug(f"Heartbeat: {self.agent_name} - {self.status}")

    async def _wait_for_shutdown(self) -> None:
        """Wait for shutdown signal"""
        await self.shutdown_event.wait()

    async def add_event(self, event: BaseEvent) -> None:
        """Add event to processing queue"""
        await self.input_queue.put(event)

    async def get_output_events(self) -> List[BaseEvent]:
        """Get processed events from output queue"""
        events = []
        while not self.output_queue.empty():
            try:
                event = self.output_queue.get_nowait()
                events.append(event)
            except asyncio.QueueEmpty:
                break
        return events

    def get_status(self) -> AgentStatus:
        """Get current agent status"""
        return AgentStatus(
            agent_id=self.agent_id,
            status=self.status,
            last_update=datetime.utcnow(),
            metrics=self.metrics,
            config=self.config
        )


class PerceptionAgent(BaseAgent):
    """Base class for Perception & Sensing agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.data_sources: List[str] = []
        self.normalization_rules: Dict[str, Any] = {}

    @abstractmethod
    async def collect_data(self) -> List[Dict[str, Any]]:
        """Collect raw data from sources"""
        pass

    @abstractmethod
    async def normalize_data(self, raw_data: Dict[str, Any]) -> BaseEvent:
        """Normalize raw data to OCSF/ECS format"""
        pass


class ContextAgent(BaseAgent):
    """Base class for Context & Understanding agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.context_window: int = 3600  # seconds
        self.correlation_rules: List[Dict[str, Any]] = []

    @abstractmethod
    async def analyze_context(self, events: List[BaseEvent]) -> List[BaseEvent]:
        """Analyze events for context and correlation"""
        pass


class MemoryAgent(BaseAgent):
    """Base class for Memory & Learning agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.memory_store: Optional[Any] = None
        self.learning_enabled: bool = True

    @abstractmethod
    async def store_memory(self, data: Any) -> str:
        """Store data in memory system"""
        pass

    @abstractmethod
    async def retrieve_memory(self, query: str) -> List[Any]:
        """Retrieve data from memory system"""
        pass

    @abstractmethod
    async def learn_from_feedback(self, feedback: Dict[str, Any]) -> None:
        """Learn from analyst feedback"""
        pass


class DecisionAgent(BaseAgent):
    """Base class for Decision & Planning agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.decision_tree: Dict[str, Any] = {}
        self.risk_threshold: float = 0.7

    @abstractmethod
    async def make_decision(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Make decision based on context"""
        pass

    @abstractmethod
    async def create_plan(self, decision: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create action plan from decision"""
        pass


class ActionAgent(BaseAgent):
    """Base class for Action & Orchestration agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.action_handlers: Dict[str, Any] = {}
        self.rollback_enabled: bool = True

    @abstractmethod
    async def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific action"""
        pass

    @abstractmethod
    async def rollback_action(self, action_id: str) -> bool:
        """Rollback a previously executed action"""
        pass

    @abstractmethod
    async def verify_action(self, action_id: str) -> bool:
        """Verify action was successful"""
        pass


class GovernanceAgent(BaseAgent):
    """Base class for Governance & Compliance agents"""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.compliance_rules: List[Dict[str, Any]] = []
        self.audit_enabled: bool = True

    @abstractmethod
    async def check_compliance(self, action: Dict[str, Any]) -> bool:
        """Check if action complies with policies"""
        pass

    @abstractmethod
    async def audit_action(self, action: Dict[str, Any]) -> None:
        """Audit an action for compliance logging"""
        pass