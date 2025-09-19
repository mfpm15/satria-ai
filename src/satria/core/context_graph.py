"""
SATRIA AI Context Graph
Neo4j-based graph for entity relationships, RCA paths, and threat intelligence correlation
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from neo4j import GraphDatabase, AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable, TransientError
import json
import uuid

from satria.models.events import BaseEvent, Entity, EntityType, AttackTechnique
from satria.core.config import settings


class GraphNode:
    """Graph node representation"""

    def __init__(self, node_id: str, labels: List[str], properties: Dict[str, Any]):
        self.node_id = node_id
        self.labels = labels
        self.properties = properties
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "labels": self.labels,
            "properties": self.properties,
            "created_at": self.created_at.isoformat()
        }


class GraphRelationship:
    """Graph relationship representation"""

    def __init__(self, from_node: str, to_node: str, rel_type: str, properties: Dict[str, Any] = None):
        self.from_node = from_node
        self.to_node = to_node
        self.rel_type = rel_type
        self.properties = properties or {}
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node,
            "to_node": self.to_node,
            "rel_type": self.rel_type,
            "properties": self.properties,
            "created_at": self.created_at.isoformat()
        }


class RCAPath:
    """Root Cause Analysis path"""

    def __init__(self, path_id: str, nodes: List[GraphNode], relationships: List[GraphRelationship]):
        self.path_id = path_id
        self.nodes = nodes
        self.relationships = relationships
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "created_at": self.created_at.isoformat()
        }


class ContextGraph:
    """SATRIA Context Graph - Neo4j integration"""

    def __init__(self):
        self.logger = logging.getLogger("satria.context_graph")
        self.driver = None
        self.session = None

        # Graph schema constraints
        self.node_constraints = {
            "User": ["user_id", "email"],
            "Host": ["hostname", "ip_address"],
            "Process": ["pid", "command_line"],
            "File": ["file_path", "hash_sha256"],
            "IP": ["address"],
            "Domain": ["fqdn"],
            "ThreatActor": ["actor_id", "name"],
            "TTP": ["technique_id"],
            "Alert": ["alert_id"],
            "Incident": ["incident_id"]
        }

        # Relationship types
        self.relationship_types = {
            "OWNS": "User owns Host/Process",
            "RUNS": "Host runs Process",
            "ACCESSES": "Process accesses File",
            "CONNECTS_TO": "Host/Process connects to IP/Domain",
            "TRIGGERS": "Event triggers Alert",
            "CORRELATES_WITH": "Alert correlates with other Alert",
            "ESCALATES_TO": "Alert escalates to Incident",
            "USES_TTP": "Actor uses Technique",
            "ATTRIBUTED_TO": "Activity attributed to Actor",
            "PARENT_OF": "Process parent relationship",
            "CHILD_OF": "Process child relationship",
            "SIMILAR_TO": "Similarity relationship",
            "COMMUNICATES_WITH": "Network communication",
            "IMPACTS": "Business impact relationship"
        }

    async def initialize(self) -> bool:
        """Initialize Neo4j connection and create constraints"""
        try:
            # Parse Neo4j URL
            url_parts = settings.neo4j_url.replace("bolt://", "").split("@")
            if len(url_parts) == 2:
                credentials, host = url_parts
                username, password = credentials.split(":")
                uri = f"bolt://{host}"
            else:
                uri = settings.neo4j_url
                username = "neo4j"
                password = "satria123"

            # Create async driver
            self.driver = AsyncGraphDatabase.driver(
                uri,
                auth=(username, password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=30
            )

            # Test connection
            await self.driver.verify_connectivity()

            # Create constraints and indexes
            await self._create_constraints()
            await self._create_indexes()

            self.logger.info("Context Graph initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Context Graph: {e}")
            return False

    async def close(self) -> None:
        """Close Neo4j connection"""
        if self.driver:
            await self.driver.close()

    async def _create_constraints(self) -> None:
        """Create uniqueness constraints for node types"""
        constraints = [
            "CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (u:User) REQUIRE u.user_id IS UNIQUE",
            "CREATE CONSTRAINT host_id_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.host_id IS UNIQUE",
            "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
            "CREATE CONSTRAINT file_hash_unique IF NOT EXISTS FOR (f:File) REQUIRE f.hash_sha256 IS UNIQUE",
            "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
            "CREATE CONSTRAINT incident_id_unique IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
            "CREATE CONSTRAINT ttp_id_unique IF NOT EXISTS FOR (t:TTP) REQUIRE t.technique_id IS UNIQUE"
        ]

        async with self.driver.session() as session:
            for constraint in constraints:
                try:
                    await session.run(constraint)
                except Exception as e:
                    self.logger.warning(f"Constraint creation warning: {e}")

    async def _create_indexes(self) -> None:
        """Create performance indexes"""
        indexes = [
            "CREATE INDEX timestamp_index IF NOT EXISTS FOR (n) ON (n.timestamp)",
            "CREATE INDEX risk_score_index IF NOT EXISTS FOR (n) ON (n.risk_score)",
            "CREATE INDEX entity_type_index IF NOT EXISTS FOR (n) ON (n.entity_type)",
            "CREATE INDEX severity_index IF NOT EXISTS FOR (a:Alert) ON (a.severity)"
        ]

        async with self.driver.session() as session:
            for index in indexes:
                try:
                    await session.run(index)
                except Exception as e:
                    self.logger.warning(f"Index creation warning: {e}")

    async def add_entity(self, entity: Entity) -> bool:
        """Add or update entity in graph"""
        try:
            # Determine Neo4j label from entity type
            label = self._get_neo4j_label(entity.entity_type)

            # Prepare properties
            properties = {
                "entity_id": entity.entity_id,
                "name": entity.name,
                "entity_type": entity.entity_type.value,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                **entity.properties
            }

            query = f"""
            MERGE (e:{label} {{entity_id: $entity_id}})
            SET e += $properties, e.updated_at = $timestamp
            RETURN e
            """

            async with self.driver.session() as session:
                result = await session.run(query, {
                    "entity_id": entity.entity_id,
                    "properties": properties,
                    "timestamp": datetime.utcnow().isoformat()
                })

                records = await result.data()
                success = len(records) > 0

                if success:
                    self.logger.debug(f"Added/updated entity {entity.entity_id}")
                return success

        except Exception as e:
            self.logger.error(f"Error adding entity {entity.entity_id}: {e}")
            return False

    async def add_relationship(self, from_entity_id: str, to_entity_id: str,
                             relationship_type: str, properties: Dict[str, Any] = None) -> bool:
        """Add relationship between entities"""
        try:
            rel_properties = {
                "created_at": datetime.utcnow().isoformat(),
                "relationship_type": relationship_type,
                **(properties or {})
            }

            query = """
            MATCH (from_node {entity_id: $from_id})
            MATCH (to_node {entity_id: $to_id})
            MERGE (from_node)-[r:RELATES {type: $rel_type}]->(to_node)
            SET r += $properties, r.updated_at = $timestamp
            RETURN r
            """

            async with self.driver.session() as session:
                result = await session.run(query, {
                    "from_id": from_entity_id,
                    "to_id": to_entity_id,
                    "rel_type": relationship_type,
                    "properties": rel_properties,
                    "timestamp": datetime.utcnow().isoformat()
                })

                records = await result.data()
                success = len(records) > 0

                if success:
                    self.logger.debug(f"Added relationship {from_entity_id} -[{relationship_type}]-> {to_entity_id}")
                return success

        except Exception as e:
            self.logger.error(f"Error adding relationship: {e}")
            return False

    async def add_event_to_graph(self, event: BaseEvent) -> bool:
        """Process event and add to context graph"""
        try:
            # Add event as Alert node
            await self._add_event_node(event)

            # Add entities from event
            for entity in event.entities:
                await self.add_entity(entity)

                # Create relationship from alert to entity
                await self.add_relationship(
                    event.event_id,
                    entity.entity_id,
                    "INVOLVES",
                    {"confidence": event.confidence.value, "risk_score": event.risk_score}
                )

            # Add MITRE ATT&CK techniques
            for technique in event.attack_techniques:
                await self._add_ttp_node(technique)
                await self.add_relationship(
                    event.event_id,
                    technique.technique_id,
                    "USES_TTP",
                    {"confidence": technique.confidence.value}
                )

            # Create correlations with recent similar events
            await self._create_event_correlations(event)

            return True

        except Exception as e:
            self.logger.error(f"Error adding event {event.event_id} to graph: {e}")
            return False

    async def _add_event_node(self, event: BaseEvent) -> None:
        """Add event as Alert node"""
        properties = {
            "alert_id": event.event_id,
            "event_type": event.event_type,
            "event_category": event.event_category.value,
            "event_class": event.event_class.value,
            "severity": event.severity.value,
            "confidence": event.confidence.value,
            "risk_score": event.risk_score or 0,
            "timestamp": event.timestamp.isoformat(),
            "source_agent": event.source_agent,
            "quality_score": event.quality_score,
            "needs_review": event.needs_review
        }

        query = """
        MERGE (a:Alert {alert_id: $alert_id})
        SET a += $properties
        RETURN a
        """

        async with self.driver.session() as session:
            await session.run(query, {
                "alert_id": event.event_id,
                "properties": properties
            })

    async def _add_ttp_node(self, technique: AttackTechnique) -> None:
        """Add MITRE ATT&CK technique node"""
        properties = {
            "technique_id": technique.technique_id,
            "technique_name": technique.technique_name,
            "tactic": technique.tactic,
            "confidence": technique.confidence.value
        }

        query = """
        MERGE (t:TTP {technique_id: $technique_id})
        SET t += $properties
        RETURN t
        """

        async with self.driver.session() as session:
            await session.run(query, {
                "technique_id": technique.technique_id,
                "properties": properties
            })

    async def _create_event_correlations(self, event: BaseEvent) -> None:
        """Create correlations with similar recent events"""
        # Find similar events within last 24 hours
        query = """
        MATCH (a:Alert)
        WHERE a.event_type = $event_type
        AND a.timestamp > $since
        AND a.alert_id <> $current_id
        WITH a,
             CASE
                WHEN abs(a.risk_score - $risk_score) < 10 THEN 0.9
                WHEN a.severity = $severity THEN 0.7
                ELSE 0.5
             END as similarity
        WHERE similarity > 0.6
        RETURN a.alert_id as related_id, similarity
        ORDER BY similarity DESC
        LIMIT 5
        """

        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()

        async with self.driver.session() as session:
            result = await session.run(query, {
                "event_type": event.event_type,
                "since": since,
                "current_id": event.event_id,
                "risk_score": event.risk_score or 0,
                "severity": event.severity.value
            })

            async for record in result:
                related_id = record["related_id"]
                similarity = record["similarity"]

                await self.add_relationship(
                    event.event_id,
                    related_id,
                    "CORRELATES_WITH",
                    {"similarity": similarity, "correlation_type": "temporal"}
                )

    async def find_rca_paths(self, start_entity_id: str, end_entity_id: str,
                           max_hops: int = 6) -> List[RCAPath]:
        """Find RCA paths between entities"""
        try:
            query = """
            MATCH path = shortestPath(
                (start {entity_id: $start_id})-[*1..$max_hops]-(end {entity_id: $end_id})
            )
            WHERE start <> end
            RETURN path
            LIMIT 10
            """

            async with self.driver.session() as session:
                result = await session.run(query, {
                    "start_id": start_entity_id,
                    "end_id": end_entity_id,
                    "max_hops": max_hops
                })

                paths = []
                async for record in result:
                    path_data = record["path"]
                    rca_path = await self._convert_neo4j_path_to_rca(path_data)
                    if rca_path:
                        paths.append(rca_path)

                return paths

        except Exception as e:
            self.logger.error(f"Error finding RCA paths: {e}")
            return []

    async def get_entity_timeline(self, entity_id: str, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Get timeline of events for entity"""
        try:
            since = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()

            query = """
            MATCH (e {entity_id: $entity_id})-[:INVOLVES]-(a:Alert)
            WHERE a.timestamp > $since
            RETURN a.alert_id, a.event_type, a.severity, a.timestamp, a.risk_score
            ORDER BY a.timestamp DESC
            """

            async with self.driver.session() as session:
                result = await session.run(query, {
                    "entity_id": entity_id,
                    "since": since
                })

                timeline = []
                async for record in result:
                    timeline.append({
                        "alert_id": record["a.alert_id"],
                        "event_type": record["a.event_type"],
                        "severity": record["a.severity"],
                        "timestamp": record["a.timestamp"],
                        "risk_score": record["a.risk_score"]
                    })

                return timeline

        except Exception as e:
            self.logger.error(f"Error getting entity timeline: {e}")
            return []

    async def get_attack_chain(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get attack chain for incident"""
        try:
            query = """
            MATCH (i:Incident {incident_id: $incident_id})-[:CONTAINS]->(a:Alert)-[:USES_TTP]->(t:TTP)
            RETURN t.technique_id, t.technique_name, t.tactic,
                   collect(a.alert_id) as alerts,
                   min(a.timestamp) as first_seen,
                   max(a.timestamp) as last_seen
            ORDER BY first_seen
            """

            async with self.driver.session() as session:
                result = await session.run(query, {"incident_id": incident_id})

                chain = []
                async for record in result:
                    chain.append({
                        "technique_id": record["t.technique_id"],
                        "technique_name": record["t.technique_name"],
                        "tactic": record["t.tactic"],
                        "alerts": record["alerts"],
                        "first_seen": record["first_seen"],
                        "last_seen": record["last_seen"]
                    })

                return chain

        except Exception as e:
            self.logger.error(f"Error getting attack chain: {e}")
            return []

    async def _convert_neo4j_path_to_rca(self, neo4j_path) -> Optional[RCAPath]:
        """Convert Neo4j path to RCAPath object"""
        try:
            path_id = str(uuid.uuid4())
            nodes = []
            relationships = []

            # Extract nodes and relationships from Neo4j path
            # This is a simplified implementation
            # In practice, you'd need to properly parse the Neo4j path object

            return RCAPath(path_id, nodes, relationships)

        except Exception as e:
            self.logger.error(f"Error converting Neo4j path: {e}")
            return None

    def _get_neo4j_label(self, entity_type: EntityType) -> str:
        """Get Neo4j label from entity type"""
        mapping = {
            EntityType.USER: "User",
            EntityType.DEVICE: "Host",
            EntityType.IP_ADDRESS: "IP",
            EntityType.DOMAIN: "Domain",
            EntityType.FILE: "File",
            EntityType.PROCESS: "Process",
            EntityType.APPLICATION: "Application",
            EntityType.SERVICE: "Service"
        }
        return mapping.get(entity_type, "Entity")

    async def cleanup_old_data(self, days_to_keep: int = 30) -> None:
        """Cleanup old graph data"""
        try:
            cutoff = (datetime.utcnow() - timedelta(days=days_to_keep)).isoformat()

            query = """
            MATCH (n)
            WHERE n.timestamp < $cutoff
            AND NOT n:TTP  // Keep TTP nodes for historical analysis
            DETACH DELETE n
            """

            async with self.driver.session() as session:
                result = await session.run(query, {"cutoff": cutoff})
                summary = await result.consume()

                self.logger.info(f"Cleaned up {summary.counters.nodes_deleted} old nodes")

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")


# Global instance
context_graph = ContextGraph()