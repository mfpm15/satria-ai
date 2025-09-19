"""
SATRIA AI - Incident Memory System
Advanced incident memory and learning system with vector embeddings and graph memory
"""

import asyncio
import logging
import numpy as np
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
from collections import defaultdict

# Vector embeddings and similarity
from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.config import Settings as ChromaSettings
import networkx as nx

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.core.context_graph import context_graph
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class MemoryType(str, Enum):
    """Types of memory stored"""
    INCIDENT_PATTERN = "incident_pattern"
    ATTACK_SEQUENCE = "attack_sequence"
    RESPONSE_EFFECTIVENESS = "response_effectiveness"
    FALSE_POSITIVE = "false_positive"
    ANALYST_DECISION = "analyst_decision"
    THREAT_CAMPAIGN = "threat_campaign"


class LearningOutcome(str, Enum):
    """Learning outcomes from incidents"""
    SUCCESSFUL_DETECTION = "successful_detection"
    MISSED_DETECTION = "missed_detection"
    FALSE_POSITIVE = "false_positive"
    EFFECTIVE_RESPONSE = "effective_response"
    INEFFECTIVE_RESPONSE = "ineffective_response"
    ESCALATION_NEEDED = "escalation_needed"
    PATTERN_RECOGNIZED = "pattern_recognized"


@dataclass
class IncidentMemory:
    """Incident memory record"""
    memory_id: str
    memory_type: MemoryType
    incident_data: Dict[str, Any]
    attack_pattern: Dict[str, Any] = field(default_factory=dict)
    entities_involved: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    response_actions: List[Dict[str, Any]] = field(default_factory=list)
    outcome: LearningOutcome = LearningOutcome.SUCCESSFUL_DETECTION
    effectiveness_score: float = 0.0
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    analyst_feedback: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    similar_incidents: List[str] = field(default_factory=list)
    embedding_vector: Optional[List[float]] = None
    knowledge_extracted: Dict[str, Any] = field(default_factory=dict)
    is_validated: bool = False


@dataclass
class AttackPattern:
    """Learned attack pattern"""
    pattern_id: str
    name: str
    description: str
    stages: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    occurrences: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    variants: List[str] = field(default_factory=list)
    countermeasures: List[str] = field(default_factory=list)


@dataclass
class LearningInsight:
    """Learning insight from memory analysis"""
    insight_id: str
    insight_type: str
    description: str
    supporting_evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    actionable_recommendations: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentMemorySystem(BaseAgent):
    """
    Advanced Incident Memory and Learning System
    Stores, analyzes, and learns from security incidents using ML and graph memory
    """

    def __init__(self):
        super().__init__(
            name="incident_memory_system",
            description="Advanced incident memory and learning system",
            version="2.0.0"
        )

        # Memory storage
        self.incident_memories: Dict[str, IncidentMemory] = {}
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.learning_insights: Dict[str, LearningInsight] = {}

        # Vector database for semantic similarity
        self.chroma_client = None
        self.memory_collection = None
        self.embedding_model = None

        # Graph memory for relationships
        self.memory_graph = nx.MultiDiGraph()

        # Learning statistics
        self.memories_stored = 0
        self.patterns_learned = 0
        self.insights_generated = 0
        self.false_positive_rate = 0.0

        # Learning parameters
        self.similarity_threshold = 0.8
        self.pattern_confidence_threshold = 0.7
        self.min_pattern_occurrences = 3
        self.memory_retention_days = 365

    async def initialize(self) -> bool:
        """Initialize the memory system"""
        try:
            # Initialize embedding model
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

            # Initialize ChromaDB
            await self._initialize_vector_database()

            # Load existing memories
            await self._load_existing_memories()

            # Start learning tasks
            asyncio.create_task(self._periodic_pattern_analysis())
            asyncio.create_task(self._periodic_insight_generation())
            asyncio.create_task(self._periodic_memory_consolidation())

            logging.info("Incident Memory System initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Memory System: {e}")
            return False

    async def _initialize_vector_database(self):
        """Initialize ChromaDB for vector similarity search"""
        try:
            # Initialize ChromaDB client
            self.chroma_client = chromadb.Client(ChromaSettings(
                chroma_db_impl="duckdb+parquet",
                persist_directory="./.chroma_db"
            ))

            # Create or get memory collection
            try:
                self.memory_collection = self.chroma_client.get_collection(
                    name="incident_memories"
                )
            except:
                self.memory_collection = self.chroma_client.create_collection(
                    name="incident_memories",
                    metadata={"description": "SATRIA AI incident memories with embeddings"}
                )

            logging.info("Vector database initialized")

        except Exception as e:
            logging.error(f"Error initializing vector database: {e}")
            # Fallback to in-memory storage
            self.chroma_client = None

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events and learn from incidents"""
        try:
            # Check if this is a significant event worth memorizing
            if await self._should_memorize_event(event):
                await self._create_incident_memory(event)

            # Check for similar past incidents
            similar_memories = await self._find_similar_incidents(event)
            if similar_memories:
                await self._apply_memory_insights(event, similar_memories)

            # Update attack patterns if applicable
            if event.risk >= 70:
                await self._update_attack_patterns(event)

            return [event]

        except Exception as e:
            logging.error(f"Error in incident memory processing: {e}")
            return [event]

    async def _should_memorize_event(self, event: BaseEvent) -> bool:
        """Determine if event should be stored in memory"""
        # Memorize high-risk events
        if event.risk >= 70:
            return True

        # Memorize events with analyst interaction
        if event.enrichment.get("analyst_reviewed"):
            return True

        # Memorize completed triage cases
        if event.event_type == "triage_case_resolved":
            return True

        # Memorize events with EDR actions taken
        if event.event_type == "edr_action_completed":
            return True

        # Memorize anomaly detections
        if event.event_type in ["behavioral_anomaly", "network_anomaly"]:
            return True

        return False

    async def _create_incident_memory(self, event: BaseEvent) -> IncidentMemory:
        """Create new incident memory from event"""
        try:
            memory_id = str(uuid.uuid4())

            # Extract key information
            entities = list(event.entity_ids.values())
            techniques = event.enrichment.get("mitre_techniques", [])

            # Determine memory type
            memory_type = self._classify_memory_type(event)

            # Create incident description for embedding
            description = self._generate_incident_description(event)

            # Generate embedding
            embedding = None
            if self.embedding_model:
                embedding = self.embedding_model.encode(description).tolist()

            # Create memory record
            memory = IncidentMemory(
                memory_id=memory_id,
                memory_type=memory_type,
                incident_data={
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "risk_score": event.risk,
                    "confidence": event.confidence,
                    "timestamp": event.timestamp.isoformat(),
                    "description": description,
                    "enrichment": event.enrichment
                },
                entities_involved=entities,
                techniques_used=techniques,
                outcome=self._determine_learning_outcome(event),
                confidence=event.confidence,
                embedding_vector=embedding,
                tags=self._generate_memory_tags(event)
            )

            # Store in memory
            self.incident_memories[memory_id] = memory
            self.memories_stored += 1

            # Store in vector database
            if self.memory_collection and embedding:
                self.memory_collection.add(
                    embeddings=[embedding],
                    documents=[description],
                    metadatas=[{
                        "memory_id": memory_id,
                        "memory_type": memory_type.value,
                        "risk_score": event.risk,
                        "timestamp": event.timestamp.isoformat()
                    }],
                    ids=[memory_id]
                )

            # Add to memory graph
            self._add_to_memory_graph(memory)

            logging.info(f"Created incident memory {memory_id} for event {event.event_id}")
            return memory

        except Exception as e:
            logging.error(f"Error creating incident memory: {e}")
            raise

    async def _find_similar_incidents(self, event: BaseEvent) -> List[IncidentMemory]:
        """Find similar past incidents using vector similarity"""
        try:
            if not self.embedding_model or not self.memory_collection:
                return []

            # Generate embedding for current event
            description = self._generate_incident_description(event)
            query_embedding = self.embedding_model.encode(description).tolist()

            # Query vector database
            results = self.memory_collection.query(
                query_embeddings=[query_embedding],
                n_results=10,
                include=["metadatas", "distances"]
            )

            similar_memories = []
            if results["metadatas"] and results["distances"]:
                for metadata, distance in zip(results["metadatas"][0], results["distances"][0]):
                    # Convert distance to similarity (ChromaDB uses cosine distance)
                    similarity = 1 - distance

                    if similarity >= self.similarity_threshold:
                        memory_id = metadata["memory_id"]
                        if memory_id in self.incident_memories:
                            memory = self.incident_memories[memory_id]
                            memory.knowledge_extracted["similarity_score"] = similarity
                            similar_memories.append(memory)

            return similar_memories

        except Exception as e:
            logging.error(f"Error finding similar incidents: {e}")
            return []

    async def _apply_memory_insights(self, event: BaseEvent, similar_memories: List[IncidentMemory]):
        """Apply insights from similar past incidents"""
        try:
            # Collect insights from similar incidents
            patterns_seen = []
            effective_responses = []
            common_techniques = []

            for memory in similar_memories:
                patterns_seen.extend(memory.attack_pattern.get("stages", []))
                if memory.outcome == LearningOutcome.EFFECTIVE_RESPONSE:
                    effective_responses.extend(memory.response_actions)
                common_techniques.extend(memory.techniques_used)

            # Generate recommendations
            recommendations = []

            # Most common techniques in similar incidents
            technique_counts = defaultdict(int)
            for technique in common_techniques:
                technique_counts[technique] += 1

            top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:3]

            if top_techniques:
                recommendations.append(f"Similar incidents often involve: {', '.join([t[0] for t in top_techniques])}")

            # Most effective responses
            response_counts = defaultdict(int)
            for response in effective_responses:
                response_type = response.get("action_type", "unknown")
                response_counts[response_type] += 1

            top_responses = sorted(response_counts.items(), key=lambda x: x[1], reverse=True)[:2]
            if top_responses:
                recommendations.append(f"Effective responses: {', '.join([r[0] for r in top_responses])}")

            # Add memory insights to event
            if "memory_insights" not in event.enrichment:
                event.enrichment["memory_insights"] = {}

            event.enrichment["memory_insights"] = {
                "similar_incidents_found": len(similar_memories),
                "average_similarity": np.mean([m.knowledge_extracted.get("similarity_score", 0) for m in similar_memories]),
                "historical_patterns": [m.attack_pattern for m in similar_memories if m.attack_pattern],
                "recommendations": recommendations,
                "memory_ids": [m.memory_id for m in similar_memories]
            }

            logging.info(f"Applied insights from {len(similar_memories)} similar incidents")

        except Exception as e:
            logging.error(f"Error applying memory insights: {e}")

    async def _update_attack_patterns(self, event: BaseEvent):
        """Update learned attack patterns based on new event"""
        try:
            # Extract attack characteristics
            event_characteristics = {
                "event_type": event.event_type,
                "techniques": event.enrichment.get("mitre_techniques", []),
                "entities": list(event.entity_ids.values()),
                "risk_score": event.risk,
                "indicators": []
            }

            # Extract indicators from enrichment
            for key, value in event.enrichment.items():
                if key in ["source_ip", "dest_ip", "file_hash", "domain", "url"]:
                    event_characteristics["indicators"].append(f"{key}:{value}")

            # Find matching attack patterns
            matching_patterns = []
            for pattern in self.attack_patterns.values():
                similarity = self._calculate_pattern_similarity(event_characteristics, pattern)
                if similarity >= 0.6:  # 60% similarity threshold
                    matching_patterns.append((pattern, similarity))

            if matching_patterns:
                # Update existing pattern
                best_match, similarity = max(matching_patterns, key=lambda x: x[1])
                best_match.occurrences += 1
                best_match.last_seen = datetime.now(timezone.utc)
                best_match.confidence = min(0.95, best_match.confidence + 0.1)

                # Add new indicators
                for indicator in event_characteristics["indicators"]:
                    if indicator not in best_match.indicators:
                        best_match.indicators.append(indicator)

                logging.info(f"Updated attack pattern {best_match.pattern_id} (similarity: {similarity:.3f})")

            elif event.risk >= 80:  # Create new pattern for high-risk events
                await self._create_new_attack_pattern(event_characteristics)

        except Exception as e:
            logging.error(f"Error updating attack patterns: {e}")

    async def _create_new_attack_pattern(self, characteristics: Dict[str, Any]):
        """Create new attack pattern from characteristics"""
        try:
            pattern_id = str(uuid.uuid4())

            # Generate pattern name based on characteristics
            primary_technique = characteristics["techniques"][0] if characteristics["techniques"] else "Unknown"
            pattern_name = f"Pattern_{primary_technique}_{characteristics['event_type']}"

            pattern = AttackPattern(
                pattern_id=pattern_id,
                name=pattern_name,
                description=f"Attack pattern involving {primary_technique} with {characteristics['event_type']} events",
                stages=[{
                    "stage": "execution",
                    "techniques": characteristics["techniques"],
                    "indicators": characteristics["indicators"],
                    "risk_level": characteristics["risk_score"]
                }],
                indicators=characteristics["indicators"],
                mitre_techniques=characteristics["techniques"],
                confidence=0.5,  # Start with medium confidence
                occurrences=1
            )

            self.attack_patterns[pattern_id] = pattern
            self.patterns_learned += 1

            logging.info(f"Created new attack pattern: {pattern_name}")

        except Exception as e:
            logging.error(f"Error creating attack pattern: {e}")

    def _calculate_pattern_similarity(self, characteristics: Dict[str, Any], pattern: AttackPattern) -> float:
        """Calculate similarity between event characteristics and attack pattern"""
        try:
            similarity_scores = []

            # Technique similarity
            if characteristics["techniques"] and pattern.mitre_techniques:
                technique_overlap = len(set(characteristics["techniques"]) & set(pattern.mitre_techniques))
                technique_union = len(set(characteristics["techniques"]) | set(pattern.mitre_techniques))
                technique_sim = technique_overlap / technique_union if technique_union > 0 else 0
                similarity_scores.append(technique_sim * 0.4)  # 40% weight

            # Indicator similarity
            if characteristics["indicators"] and pattern.indicators:
                indicator_overlap = len(set(characteristics["indicators"]) & set(pattern.indicators))
                indicator_union = len(set(characteristics["indicators"]) | set(pattern.indicators))
                indicator_sim = indicator_overlap / indicator_union if indicator_union > 0 else 0
                similarity_scores.append(indicator_sim * 0.3)  # 30% weight

            # Risk score similarity
            if pattern.stages:
                pattern_risk = max([stage.get("risk_level", 0) for stage in pattern.stages])
                risk_diff = abs(characteristics["risk_score"] - pattern_risk) / 100.0
                risk_sim = max(0, 1 - risk_diff)
                similarity_scores.append(risk_sim * 0.3)  # 30% weight

            return sum(similarity_scores) if similarity_scores else 0.0

        except Exception as e:
            logging.error(f"Error calculating pattern similarity: {e}")
            return 0.0

    async def _periodic_insight_generation(self):
        """Periodically generate learning insights from memory"""
        while self.is_running:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Analyze false positives
                await self._analyze_false_positives()

                # Analyze response effectiveness
                await self._analyze_response_effectiveness()

                # Detect emerging patterns
                await self._detect_emerging_patterns()

                # Generate operational insights
                await self._generate_operational_insights()

            except Exception as e:
                logging.error(f"Error in periodic insight generation: {e}")
                await asyncio.sleep(3600)

    async def _analyze_false_positives(self):
        """Analyze false positive patterns"""
        try:
            fp_memories = [m for m in self.incident_memories.values()
                          if m.outcome == LearningOutcome.FALSE_POSITIVE]

            if len(fp_memories) < 5:
                return

            # Group by common characteristics
            fp_patterns = defaultdict(list)
            for memory in fp_memories:
                key = f"{memory.incident_data.get('event_type', 'unknown')}_{memory.memory_type.value}"
                fp_patterns[key].append(memory)

            # Generate insights for patterns with multiple occurrences
            for pattern_key, memories in fp_patterns.items():
                if len(memories) >= 3:
                    insight = LearningInsight(
                        insight_id=str(uuid.uuid4()),
                        insight_type="false_positive_pattern",
                        description=f"Recurring false positive pattern detected in {pattern_key}",
                        supporting_evidence=[m.memory_id for m in memories],
                        confidence=min(0.9, len(memories) / 10.0),
                        actionable_recommendations=[
                            f"Review detection rules for {pattern_key}",
                            "Consider adjusting thresholds or adding exclusions",
                            "Implement additional context checks"
                        ]
                    )

                    self.learning_insights[insight.insight_id] = insight
                    self.insights_generated += 1

                    logging.info(f"Generated false positive insight: {pattern_key}")

        except Exception as e:
            logging.error(f"Error analyzing false positives: {e}")

    def _classify_memory_type(self, event: BaseEvent) -> MemoryType:
        """Classify the type of memory based on event"""
        if event.event_type == "triage_case_resolved":
            return MemoryType.ANALYST_DECISION
        elif event.event_type == "edr_action_completed":
            return MemoryType.RESPONSE_EFFECTIVENESS
        elif "anomaly" in event.event_type:
            return MemoryType.INCIDENT_PATTERN
        elif event.risk >= 80:
            return MemoryType.ATTACK_SEQUENCE
        else:
            return MemoryType.INCIDENT_PATTERN

    def _generate_incident_description(self, event: BaseEvent) -> str:
        """Generate textual description for embedding"""
        description_parts = []

        description_parts.append(f"Event type: {event.event_type}")
        description_parts.append(f"Risk score: {event.risk}")

        if event.message:
            description_parts.append(f"Description: {event.message}")

        # Add entity information
        if event.entity_ids:
            entities = ", ".join([f"{k}: {v}" for k, v in event.entity_ids.items()])
            description_parts.append(f"Entities: {entities}")

        # Add key enrichment data
        enrichment_keys = ["platform", "detection_type", "source_ip", "dest_ip", "file_path"]
        for key in enrichment_keys:
            if key in event.enrichment:
                description_parts.append(f"{key}: {event.enrichment[key]}")

        return ". ".join(description_parts)

    def _determine_learning_outcome(self, event: BaseEvent) -> LearningOutcome:
        """Determine learning outcome from event"""
        if event.enrichment.get("false_positive"):
            return LearningOutcome.FALSE_POSITIVE
        elif event.risk >= 80 and event.confidence >= 0.8:
            return LearningOutcome.SUCCESSFUL_DETECTION
        elif event.enrichment.get("edr_actions_effective"):
            return LearningOutcome.EFFECTIVE_RESPONSE
        else:
            return LearningOutcome.SUCCESSFUL_DETECTION

    def _generate_memory_tags(self, event: BaseEvent) -> List[str]:
        """Generate tags for memory indexing"""
        tags = [event.event_type, event.event_category.value]

        if event.risk >= 80:
            tags.append("high_risk")
        elif event.risk >= 50:
            tags.append("medium_risk")
        else:
            tags.append("low_risk")

        # Add platform tags
        if "platform" in event.enrichment:
            tags.append(f"platform_{event.enrichment['platform']}")

        return tags

    def _add_to_memory_graph(self, memory: IncidentMemory):
        """Add memory to relationship graph"""
        try:
            # Add memory node
            self.memory_graph.add_node(
                memory.memory_id,
                memory_type=memory.memory_type.value,
                timestamp=memory.timestamp.isoformat(),
                risk_score=memory.incident_data.get("risk_score", 0)
            )

            # Connect to entities
            for entity in memory.entities_involved:
                entity_id = f"entity:{entity}"
                if not self.memory_graph.has_node(entity_id):
                    self.memory_graph.add_node(entity_id, type="entity", value=entity)

                self.memory_graph.add_edge(
                    memory.memory_id,
                    entity_id,
                    relationship="involves"
                )

            # Connect to techniques
            for technique in memory.techniques_used:
                technique_id = f"technique:{technique}"
                if not self.memory_graph.has_node(technique_id):
                    self.memory_graph.add_node(technique_id, type="technique", value=technique)

                self.memory_graph.add_edge(
                    memory.memory_id,
                    technique_id,
                    relationship="uses"
                )

        except Exception as e:
            logging.error(f"Error adding to memory graph: {e}")

    async def get_memory_insights(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get memory insights based on query"""
        try:
            insights = []

            if not self.embedding_model or not self.memory_collection:
                return insights

            # Generate query embedding
            query_embedding = self.embedding_model.encode(query).tolist()

            # Search similar memories
            results = self.memory_collection.query(
                query_embeddings=[query_embedding],
                n_results=limit,
                include=["metadatas", "distances", "documents"]
            )

            if results["metadatas"]:
                for i, metadata in enumerate(results["metadatas"][0]):
                    memory_id = metadata["memory_id"]
                    if memory_id in self.incident_memories:
                        memory = self.incident_memories[memory_id]
                        similarity = 1 - results["distances"][0][i]

                        insights.append({
                            "memory_id": memory_id,
                            "description": results["documents"][0][i],
                            "similarity": similarity,
                            "memory_type": memory.memory_type.value,
                            "outcome": memory.outcome.value,
                            "timestamp": memory.timestamp.isoformat(),
                            "tags": memory.tags
                        })

            return insights

        except Exception as e:
            logging.error(f"Error getting memory insights: {e}")
            return []

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Save memory data to persistent storage
            await self._save_memory_data()

            # Close vector database connections
            if self.chroma_client:
                # ChromaDB doesn't have explicit close method, just clear reference
                self.chroma_client = None

            # Clear in-memory data
            self.incident_memories.clear()
            self.memory_embeddings.clear()
            self.pattern_graph.clear()

            self.logger.info("Incident memory system cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    async def _save_memory_data(self) -> None:
        """Save memory data to persistent storage"""
        try:
            # In production, save to persistent storage
            self.logger.debug(f"Saved {len(self.incident_memories)} memories (mock)")
        except Exception as e:
            self.logger.error(f"Error saving memory data: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get memory system metrics"""
        # Calculate memory type distribution
        memory_types = defaultdict(int)
        for memory in self.incident_memories.values():
            memory_types[memory.memory_type.value] += 1

        # Calculate learning outcomes distribution
        outcomes = defaultdict(int)
        for memory in self.incident_memories.values():
            outcomes[memory.outcome.value] += 1

        return {
            **super().get_metrics(),
            "memories_stored": self.memories_stored,
            "patterns_learned": self.patterns_learned,
            "insights_generated": self.insights_generated,
            "memory_types": dict(memory_types),
            "learning_outcomes": dict(outcomes),
            "memory_graph_nodes": self.memory_graph.number_of_nodes(),
            "memory_graph_edges": self.memory_graph.number_of_edges(),
            "vector_db_status": "active" if self.memory_collection else "inactive"
        }


# Global instance
incident_memory_system = IncidentMemorySystem()