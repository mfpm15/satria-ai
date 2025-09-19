"""
Enhanced Agent Orchestrator Methods for Phase 2 Integration
Additional methods for the enhanced orchestrator
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from satria.models.events import BaseEvent


async def _initialize_core_agents(self) -> None:
    """Initialize core agents in proper order"""
    try:
        self.logger.info("🔧 Initializing core AI agents...")

        # Initialize in dependency order
        initialization_order = [
            "perception",   # Data collection first
            "context",      # Context analysis
            "intelligence", # AI/ML analysis
            "memory",       # Learning systems
            "decision",     # Decision making
            "orchestration", # Response execution
            "copilot"       # Human interaction
        ]

        for layer_name in initialization_order:
            agents = self.core_agents.get(layer_name, [])
            if not agents:
                continue

            self.logger.info(f"Initializing {layer_name} layer: {len(agents)} agents")

            # Initialize agents in parallel within each layer
            init_tasks = []
            for agent in agents:
                task = asyncio.create_task(self._initialize_single_agent(agent, layer_name))
                init_tasks.append(task)

            # Wait for layer completion
            results = await asyncio.gather(*init_tasks, return_exceptions=True)

            # Check results
            success_count = 0
            for i, result in enumerate(results):
                agent_name = agents[i].name
                if isinstance(result, Exception):
                    self.logger.error(f"❌ Failed to initialize {agent_name}: {result}")
                elif result:
                    self.logger.info(f"✅ {agent_name} initialized")
                    success_count += 1
                else:
                    self.logger.warning(f"⚠️ {agent_name} initialization failed")

            self.logger.info(f"{layer_name} layer: {success_count}/{len(agents)} agents initialized")

        self.logger.info("🎯 Core agents initialization complete!")

    except Exception as e:
        self.logger.error(f"Error initializing core agents: {e}")
        raise


async def _initialize_single_agent(self, agent, layer_name: str) -> bool:
    """Initialize a single agent with error handling"""
    try:
        success = await agent.initialize()
        if success:
            # Register with orchestrator
            await self.register_agent(agent)

            # Add to layer group
            if layer_name not in self.agent_groups:
                self.agent_groups[layer_name] = set()
            self.agent_groups[layer_name].add(agent.name)

        return success

    except Exception as e:
        self.logger.error(f"Error initializing {agent.name}: {e}")
        return False


async def _setup_enhanced_routes(self) -> None:
    """Setup enhanced message routing for Phase 2"""
    try:
        self.logger.info("Setting up enhanced routing rules...")

        enhanced_routes = [
            # Perception Layer Routes
            MessageRoute(
                source_pattern="log_collector",
                destination_agents=["risk_scorer", "behavioral_anomaly_detector"],
                priority=8
            ),
            MessageRoute(
                source_pattern="edr_connector",
                destination_agents=["risk_scorer", "threat_intelligence_engine", "network_anomaly_detector"],
                priority=9
            ),

            # Intelligence Layer Routes
            MessageRoute(
                source_pattern="*",
                destination_agents=["behavioral_anomaly_detector", "network_anomaly_detector"],
                conditions={"risk": ">= 40"},
                priority=7
            ),
            MessageRoute(
                source_pattern="*",
                destination_agents=["threat_intelligence_engine"],
                conditions={"enrichment.source_ip": "exists"},
                priority=6
            ),

            # Memory and Learning Routes
            MessageRoute(
                source_pattern="*",
                destination_agents=["incident_memory_system"],
                conditions={"risk": ">= 50"},
                priority=5
            ),

            # Decision Layer Routes
            MessageRoute(
                source_pattern="*",
                destination_agents=["triage_planner"],
                conditions={"risk": ">= 60"},
                priority=8
            ),

            # Orchestration Routes
            MessageRoute(
                source_pattern="triage_case_created",
                destination_agents=["edr_orchestrator"],
                priority=9
            ),
            MessageRoute(
                source_pattern="*",
                destination_agents=["edr_orchestrator"],
                conditions={"risk": ">= 80"},
                priority=10
            ),

            # Copilot Integration
            MessageRoute(
                source_pattern="analyst_query",
                destination_agents=["analyst_copilot"],
                priority=10
            )
        ]

        self.message_routes.extend(enhanced_routes)
        self.logger.info(f"Enhanced routing configured: {len(enhanced_routes)} rules")

    except Exception as e:
        self.logger.error(f"Error setting up enhanced routes: {e}")


async def _start_intelligent_pipeline(self) -> None:
    """Start intelligent event processing pipeline"""
    try:
        self.logger.info("Starting intelligent event processing pipeline...")

        # Create pipeline processor task
        asyncio.create_task(self._intelligent_pipeline_processor())

        # Create performance monitoring task
        asyncio.create_task(self._pipeline_performance_monitor())

        self.logger.info("Intelligent pipeline started successfully")

    except Exception as e:
        self.logger.error(f"Error starting intelligent pipeline: {e}")


async def _intelligent_pipeline_processor(self) -> None:
    """Process events through intelligent pipeline"""
    while self.state == OrchestratorState.RUNNING:
        try:
            # This would integrate with event bus to process events
            # through the complete AI pipeline in proper order
            await asyncio.sleep(1)

        except Exception as e:
            self.logger.error(f"Error in intelligent pipeline: {e}")
            await asyncio.sleep(5)


async def _pipeline_performance_monitor(self) -> None:
    """Monitor pipeline performance and optimize routing"""
    while self.state == OrchestratorState.RUNNING:
        try:
            # Monitor agent performance
            for layer_name, agents in self.core_agents.items():
                layer_metrics = {}
                for agent in agents:
                    if hasattr(agent, 'get_metrics'):
                        metrics = agent.get_metrics()
                        layer_metrics[agent.name] = metrics

                # Log layer performance
                if layer_metrics:
                    avg_processing_time = sum(
                        m.get('avg_processing_time', 0) for m in layer_metrics.values()
                    ) / len(layer_metrics)

                    self.logger.debug(f"{layer_name} layer avg processing: {avg_processing_time:.3f}s")

            await asyncio.sleep(300)  # Monitor every 5 minutes

        except Exception as e:
            self.logger.error(f"Error in pipeline monitoring: {e}")
            await asyncio.sleep(60)


async def process_event_intelligently(self, event: BaseEvent) -> BaseEvent:
    """Process event through intelligent AI pipeline"""
    try:
        self.metrics["pipeline_events_processed"] += 1
        processing_start = datetime.now(timezone.utc)

        # Phase 1: Context and Risk Analysis
        if event.risk == 0:  # Not yet scored
            await self._route_to_layer(event, "context")

        # Phase 2: Intelligence Analysis (parallel)
        if event.risk >= 40:
            intelligence_tasks = []
            for agent in self.core_agents["intelligence"]:
                task = asyncio.create_task(self._process_with_agent(agent, event))
                intelligence_tasks.append(task)

            # Wait for intelligence analysis
            results = await asyncio.gather(*intelligence_tasks, return_exceptions=True)

            # Consolidate intelligence results
            event = self._consolidate_intelligence_results(event, results)
            self.metrics["intelligence_analyses"] += 1

        # Phase 3: Memory and Learning
        if event.risk >= 50:
            await self._route_to_layer(event, "memory")

        # Phase 4: Decision Making
        if event.risk >= 60:
            await self._route_to_layer(event, "decision")

        # Phase 5: Automated Response
        if event.risk >= 80:
            await self._route_to_layer(event, "orchestration")

        # Add processing metadata
        processing_time = (datetime.now(timezone.utc) - processing_start).total_seconds()
        event.enrichment["intelligent_processing"] = {
            "processing_time": processing_time,
            "pipeline_version": "2.0",
            "layers_processed": self._get_layers_processed(event)
        }

        return event

    except Exception as e:
        self.logger.error(f"Error in intelligent processing: {e}")
        return event


async def _route_to_layer(self, event: BaseEvent, layer_name: str) -> None:
    """Route event to specific agent layer"""
    try:
        agents = self.core_agents.get(layer_name, [])
        for agent in agents:
            if agent.is_running:
                await agent.process_event(event)

    except Exception as e:
        self.logger.error(f"Error routing to {layer_name} layer: {e}")


async def _process_with_agent(self, agent, event: BaseEvent) -> BaseEvent:
    """Process event with single agent safely"""
    try:
        if agent.is_running:
            result = await asyncio.wait_for(
                agent.process_event(event),
                timeout=30.0
            )
            return result or event
        return event

    except asyncio.TimeoutError:
        self.logger.warning(f"Agent {agent.name} processing timeout")
        return event
    except Exception as e:
        self.logger.error(f"Error processing with {agent.name}: {e}")
        return event


def _consolidate_intelligence_results(self, event: BaseEvent, results: List) -> BaseEvent:
    """Consolidate results from intelligence agents"""
    try:
        # Collect all intelligence insights
        intelligence_insights = []
        max_risk_boost = 0

        for result in results:
            if isinstance(result, BaseEvent):
                # Check for intelligence-specific enrichments
                if "anomaly_detection" in result.enrichment:
                    intelligence_insights.append(result.enrichment["anomaly_detection"])

                if "threat_intelligence" in result.enrichment:
                    intelligence_insights.append(result.enrichment["threat_intelligence"])
                    max_risk_boost = max(max_risk_boost, 20)  # TI boost

                if "behavioral_anomaly" in result.enrichment:
                    intelligence_insights.append(result.enrichment["behavioral_anomaly"])
                    max_risk_boost = max(max_risk_boost, 15)  # Behavioral boost

        # Apply intelligence boost to risk score
        if max_risk_boost > 0:
            event.risk = min(100, event.risk + max_risk_boost)

        # Consolidate insights
        if intelligence_insights:
            event.enrichment["intelligence_analysis"] = {
                "insights": intelligence_insights,
                "risk_boost": max_risk_boost,
                "analysis_count": len(intelligence_insights)
            }

        return event

    except Exception as e:
        self.logger.error(f"Error consolidating intelligence results: {e}")
        return event


def _get_layers_processed(self, event: BaseEvent) -> List[str]:
    """Get list of processing layers from event enrichment"""
    layers = []
    enrichment = event.enrichment

    if "risk_analysis" in enrichment:
        layers.append("context")
    if "intelligence_analysis" in enrichment:
        layers.append("intelligence")
    if "memory_insights" in enrichment:
        layers.append("memory")
    if "triage_case" in enrichment:
        layers.append("decision")
    if "edr_actions" in enrichment:
        layers.append("orchestration")

    return layers


async def get_enhanced_system_status(self) -> Dict[str, Any]:
    """Get comprehensive enhanced system status"""
    try:
        status = {
            "orchestrator_version": "2.0",
            "phase": "Intelligence (Phase 2)",
            "overall_health": "healthy",
            "processing_pipeline": {},
            "intelligence_layers": {},
            "performance_metrics": self.metrics
        }

        # Check each layer health
        for layer_name, agents in self.core_agents.items():
            layer_status = {
                "agents": len(agents),
                "healthy": 0,
                "total_events": 0,
                "avg_processing_time": 0.0
            }

            total_time = 0
            total_events = 0

            for agent in agents:
                if hasattr(agent, 'get_metrics'):
                    metrics = agent.get_metrics()
                    if metrics.get('is_healthy', True):
                        layer_status["healthy"] += 1

                    events = metrics.get('events_processed', 0)
                    processing_time = metrics.get('avg_processing_time', 0)

                    total_events += events
                    total_time += processing_time * events

            layer_status["total_events"] = total_events
            if total_events > 0:
                layer_status["avg_processing_time"] = total_time / total_events

            status["intelligence_layers"][layer_name] = layer_status

        # Overall health assessment
        total_agents = sum(len(agents) for agents in self.core_agents.values())
        healthy_agents = sum(layer["healthy"] for layer in status["intelligence_layers"].values())

        if healthy_agents >= total_agents * 0.9:
            status["overall_health"] = "healthy"
        elif healthy_agents >= total_agents * 0.7:
            status["overall_health"] = "degraded"
        else:
            status["overall_health"] = "unhealthy"

        return status

    except Exception as e:
        self.logger.error(f"Error getting enhanced status: {e}")
        return {"error": str(e)}


# Attach methods to AgentOrchestrator class
def enhance_orchestrator():
    """Enhance the orchestrator with Phase 2 methods"""
    import types
    from satria.core.agent_orchestrator import AgentOrchestrator

    # Add enhanced methods
    AgentOrchestrator._initialize_core_agents = _initialize_core_agents
    AgentOrchestrator._initialize_single_agent = _initialize_single_agent
    AgentOrchestrator._setup_enhanced_routes = _setup_enhanced_routes
    AgentOrchestrator._start_intelligent_pipeline = _start_intelligent_pipeline
    AgentOrchestrator._intelligent_pipeline_processor = _intelligent_pipeline_processor
    AgentOrchestrator._pipeline_performance_monitor = _pipeline_performance_monitor
    AgentOrchestrator.process_event_intelligently = process_event_intelligently
    AgentOrchestrator._route_to_layer = _route_to_layer
    AgentOrchestrator._process_with_agent = _process_with_agent
    AgentOrchestrator._consolidate_intelligence_results = _consolidate_intelligence_results
    AgentOrchestrator._get_layers_processed = _get_layers_processed
    AgentOrchestrator.get_enhanced_system_status = get_enhanced_system_status