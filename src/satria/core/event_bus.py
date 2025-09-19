"""
SATRIA AI Event Bus
High-performance event streaming with Kafka integration
"""

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Union
from datetime import datetime
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import redis.asyncio as aioredis

from satria.models.events import BaseEvent, EventBatch
from satria.core.config import settings


class EventBusError(Exception):
    """Event Bus specific errors"""
    pass


class EventRouter:
    """Routes events to appropriate destinations"""

    def __init__(self):
        self.routes: Dict[str, List[str]] = {}
        self.logger = logging.getLogger("satria.event_bus.router")

    def add_route(self, event_type: str, destination: str) -> None:
        """Add routing rule for event type"""
        if event_type not in self.routes:
            self.routes[event_type] = []

        if destination not in self.routes[event_type]:
            self.routes[event_type].append(destination)
            self.logger.debug(f"Added route: {event_type} -> {destination}")

    def get_destinations(self, event: BaseEvent) -> List[str]:
        """Get destinations for an event"""
        destinations = set()

        # Add explicitly defined destinations from event
        destinations.update(event.destinations)

        # Add destinations from routing rules
        if event.event_type in self.routes:
            destinations.update(self.routes[event.event_type])

        # Add destinations for event category
        category_routes = self.routes.get(f"category:{event.event_category}", [])
        destinations.update(category_routes)

        return list(destinations)


class EventBus:
    """SATRIA AI Event Bus - Kafka-based event streaming"""

    def __init__(self):
        self.logger = logging.getLogger("satria.event_bus")
        self.router = EventRouter()
        self.producer: Optional[KafkaProducer] = None
        self.consumers: Dict[str, KafkaConsumer] = {}
        self.redis: Optional[aioredis.Redis] = None
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.running = False

        # Performance metrics
        self.metrics = {
            "events_published": 0,
            "events_consumed": 0,
            "errors": 0,
            "last_activity": None
        }

    async def initialize(self) -> bool:
        """Initialize Event Bus connections"""
        try:
            # Initialize Kafka producer
            self.producer = KafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap_servers.split(','),
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                acks='all',
                retries=3,
                batch_size=16384,
                linger_ms=10,
                max_request_size=1048576
            )

            # Initialize Redis for fast messaging
            self.redis = await aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20
            )

            # Test connections
            await self.redis.ping()

            self.logger.info("Event Bus initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Event Bus: {e}")
            return False

    async def shutdown(self) -> None:
        """Shutdown Event Bus gracefully"""
        self.running = False

        if self.producer:
            self.producer.close()

        for consumer in self.consumers.values():
            consumer.close()

        if self.redis:
            await self.redis.close()

        self.logger.info("Event Bus shutdown completed")

    def add_route(self, event_type: str, destination: str) -> None:
        """Add routing rule"""
        self.router.add_route(event_type, destination)

    def subscribe(self, event_type: str, handler: Callable[[BaseEvent], None]) -> None:
        """Subscribe to event type with handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []

        self.event_handlers[event_type].append(handler)
        self.logger.info(f"Subscribed handler to {event_type}")

    async def publish(self, event: Union[BaseEvent, EventBatch]) -> bool:
        """Publish event to the bus"""
        try:
            if isinstance(event, EventBatch):
                return await self._publish_batch(event)
            else:
                return await self._publish_single_event(event)

        except Exception as e:
            self.logger.error(f"Failed to publish event: {e}")
            self.metrics["errors"] += 1
            return False

    async def _publish_single_event(self, event: BaseEvent) -> bool:
        """Publish single event"""
        try:
            # Get routing destinations
            destinations = self.router.get_destinations(event)

            # Serialize event
            event_data = event.dict()
            event_data["_published_at"] = datetime.utcnow().isoformat()

            # Publish to Kafka topics (reliable)
            for destination in destinations:
                topic = f"{settings.kafka_topic_prefix}_{destination}"
                future = self.producer.send(topic, value=event_data)

                # Wait for delivery confirmation (optional, can be async)
                record_metadata = future.get(timeout=10)
                self.logger.debug(f"Event {event.event_id} sent to {topic}")

            # Publish to Redis for real-time consumption (fast)
            if destinations:
                await self.redis.publish(
                    f"{settings.kafka_topic_prefix}_realtime",
                    json.dumps(event_data, default=str)
                )

            # Update metrics
            self.metrics["events_published"] += 1
            self.metrics["last_activity"] = datetime.utcnow()

            return True

        except KafkaError as e:
            self.logger.error(f"Kafka error publishing event {event.event_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error publishing event {event.event_id}: {e}")
            return False

    async def _publish_batch(self, batch: EventBatch) -> bool:
        """Publish batch of events"""
        try:
            success_count = 0

            for event in batch.events:
                if await self._publish_single_event(event):
                    success_count += 1

            self.logger.info(f"Published batch {batch.batch_id}: {success_count}/{len(batch.events)} events")
            return success_count == len(batch.events)

        except Exception as e:
            self.logger.error(f"Error publishing batch {batch.batch_id}: {e}")
            return False

    async def consume_events(self, topics: List[str], group_id: str) -> None:
        """Start consuming events from topics"""
        try:
            # Create Kafka consumer
            consumer = KafkaConsumer(
                *[f"{settings.kafka_topic_prefix}_{topic}" for topic in topics],
                bootstrap_servers=settings.kafka_bootstrap_servers.split(','),
                group_id=group_id,
                auto_offset_reset='latest',
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                consumer_timeout_ms=1000,
                max_poll_records=100
            )

            self.consumers[group_id] = consumer
            self.running = True

            self.logger.info(f"Started consuming topics {topics} with group {group_id}")

            # Consumption loop
            while self.running:
                try:
                    message_pack = consumer.poll(timeout_ms=1000)

                    for topic_partition, messages in message_pack.items():
                        for message in messages:
                            await self._handle_consumed_event(message.value)

                    # Commit offsets
                    consumer.commit()

                except Exception as e:
                    self.logger.error(f"Error consuming events: {e}")
                    self.metrics["errors"] += 1
                    await asyncio.sleep(1)

        except Exception as e:
            self.logger.error(f"Failed to start event consumer: {e}")

    async def _handle_consumed_event(self, event_data: Dict[str, Any]) -> None:
        """Handle consumed event"""
        try:
            # Reconstruct event object
            event = BaseEvent(**event_data)

            # Call registered handlers
            handlers = self.event_handlers.get(event.event_type, [])
            handlers.extend(self.event_handlers.get("*", []))  # Universal handlers

            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    self.logger.error(f"Error in event handler: {e}")

            # Update metrics
            self.metrics["events_consumed"] += 1
            self.metrics["last_activity"] = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error handling consumed event: {e}")

    async def get_event_history(self, event_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events of specific type from Redis cache"""
        try:
            cache_key = f"{settings.redis_cache_prefix}:history:{event_type}"
            events = await self.redis.lrange(cache_key, 0, limit - 1)

            return [json.loads(event) for event in events]

        except Exception as e:
            self.logger.error(f"Error retrieving event history: {e}")
            return []

    def get_metrics(self) -> Dict[str, Any]:
        """Get Event Bus performance metrics"""
        return {
            **self.metrics,
            "active_consumers": len(self.consumers),
            "registered_handlers": sum(len(handlers) for handlers in self.event_handlers.values()),
            "routing_rules": len(self.router.routes)
        }


# Global Event Bus instance
event_bus = EventBus()


# Convenience functions
async def publish_event(event: Union[BaseEvent, EventBatch]) -> bool:
    """Publish event to global event bus"""
    return await event_bus.publish(event)


def subscribe_to_events(event_type: str, handler: Callable[[BaseEvent], None]) -> None:
    """Subscribe to events on global event bus"""
    event_bus.subscribe(event_type, handler)


def add_event_route(event_type: str, destination: str) -> None:
    """Add routing rule to global event bus"""
    event_bus.add_route(event_type, destination)