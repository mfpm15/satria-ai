"""
SATRIA AI Purple Team Collaboration Framework
Real-time communication and coordination system for red-blue team collaboration
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import json
import logging
from pathlib import Path
import websockets
import threading
from collections import defaultdict

logger = logging.getLogger(__name__)

class MessageType(Enum):
    CHAT = "chat"
    NOTIFICATION = "notification"
    ALERT = "alert"
    STATUS_UPDATE = "status_update"
    OBJECTIVE_UPDATE = "objective_update"
    TACTICAL_BRIEFING = "tactical_briefing"
    LESSONS_LEARNED = "lessons_learned"
    SYSTEM_MESSAGE = "system_message"

class MessagePriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CollaborationChannel(Enum):
    GLOBAL = "global"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    WHITE_TEAM = "white_team"
    CROSS_TEAM = "cross_team"
    OBSERVERS = "observers"
    TACTICAL = "tactical"
    DEBRIEF = "debrief"

@dataclass
class Message:
    id: str
    sender_id: str
    sender_name: str
    channel: CollaborationChannel
    type: MessageType
    priority: MessagePriority
    content: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    thread_id: Optional[str] = None
    reactions: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    attachments: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class CollaborationSession:
    id: str
    exercise_id: str
    name: str
    participants: Dict[str, Dict[str, Any]]
    channels: Dict[CollaborationChannel, List[Message]]
    active_threads: Dict[str, List[Message]]
    shared_artifacts: Dict[str, Any]
    real_time_board: Dict[str, Any]
    created_at: datetime
    last_activity: datetime

@dataclass
class TacticalUpdate:
    id: str
    timestamp: datetime
    team: str
    phase: str
    status: str
    progress: Dict[str, Any]
    next_actions: List[str]
    blockers: List[str]
    key_findings: List[str]

@dataclass
class SharedArtifact:
    id: str
    name: str
    type: str
    content: Any
    created_by: str
    created_at: datetime
    tags: List[str]
    access_level: str
    version: int = 1

class CollaborationFramework:
    def __init__(self, data_dir: str = "data/collaboration"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.sessions: Dict[str, CollaborationSession] = {}
        self.active_connections: Dict[str, Any] = {}
        self.message_handlers: Dict[MessageType, List[Callable]] = defaultdict(list)
        self.collaboration_rules: Dict[str, Any] = {}

        self._initialize_collaboration_rules()
        self._setup_websocket_server()

    def _initialize_collaboration_rules(self):
        """Initialize collaboration rules and protocols"""
        self.collaboration_rules = {
            "communication_protocols": {
                "red_team_isolation": {
                    "description": "Red team operates in isolation during attack phases",
                    "channels_allowed": [CollaborationChannel.RED_TEAM, CollaborationChannel.TACTICAL],
                    "cross_team_communication": False,
                    "exceptions": ["critical_safety", "exercise_pause"]
                },
                "blue_team_coordination": {
                    "description": "Blue team coordinates defense activities",
                    "channels_allowed": [CollaborationChannel.BLUE_TEAM, CollaborationChannel.GLOBAL],
                    "real_time_sharing": True,
                    "artifact_sharing": True
                },
                "purple_collaboration": {
                    "description": "Joint collaboration phases",
                    "channels_allowed": "all",
                    "knowledge_sharing": True,
                    "real_time_feedback": True
                }
            },
            "information_sharing": {
                "real_time_indicators": {
                    "allowed_teams": ["blue_team", "white_team"],
                    "data_types": ["iocs", "network_activity", "system_alerts"],
                    "sanitization_required": False
                },
                "attack_methodologies": {
                    "sharing_phase": "post_exercise",
                    "detail_level": "high",
                    "sanitization_required": True
                },
                "defense_strategies": {
                    "sharing_phase": "during_exercise",
                    "allowed_teams": ["blue_team", "white_team"],
                    "real_time_updates": True
                }
            },
            "collaboration_phases": {
                "pre_exercise": {
                    "all_teams_communication": True,
                    "scenario_briefing": True,
                    "tool_coordination": True
                },
                "active_exercise": {
                    "team_isolation": True,
                    "tactical_updates": True,
                    "safety_communications": True
                },
                "post_exercise": {
                    "full_collaboration": True,
                    "lessons_learned": True,
                    "knowledge_transfer": True
                }
            }
        }

    def _setup_websocket_server(self):
        """Setup WebSocket server for real-time communication"""
        # In a real implementation, this would set up actual WebSocket server
        # For now, we'll simulate with async message queues
        self.message_queues = defaultdict(asyncio.Queue)
        self.broadcast_queues = defaultdict(list)

    async def create_collaboration_session(self, exercise_id: str, session_config: Dict[str, Any]) -> str:
        """Create a new collaboration session for an exercise"""
        try:
            session_id = f"collab_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            session = CollaborationSession(
                id=session_id,
                exercise_id=exercise_id,
                name=session_config.get("name", f"Collaboration Session {session_id}"),
                participants={},
                channels={channel: [] for channel in CollaborationChannel},
                active_threads={},
                shared_artifacts={},
                real_time_board={
                    "attack_timeline": [],
                    "defense_actions": [],
                    "indicators": [],
                    "metrics": {},
                    "shared_notes": []
                },
                created_at=datetime.now(),
                last_activity=datetime.now()
            )

            self.sessions[session_id] = session
            await self._save_session(session)

            # Send welcome message
            welcome_msg = await self._create_system_message(
                session_id,
                CollaborationChannel.GLOBAL,
                f"Collaboration session '{session.name}' created for exercise {exercise_id}",
                MessagePriority.MEDIUM
            )

            logger.info(f"Created collaboration session: {session_id}")
            return session_id

        except Exception as e:
            logger.error(f"Failed to create collaboration session: {str(e)}")
            raise

    async def add_participant(self, session_id: str, user_id: str, user_data: Dict[str, Any]) -> bool:
        """Add a participant to the collaboration session"""
        try:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]

            participant_info = {
                "user_id": user_id,
                "name": user_data["name"],
                "role": user_data["role"],
                "team": user_data["team"],
                "permissions": user_data.get("permissions", []),
                "joined_at": datetime.now().isoformat(),
                "status": "online",
                "last_seen": datetime.now().isoformat()
            }

            session.participants[user_id] = participant_info

            # Send join notification
            join_msg = await self._create_system_message(
                session_id,
                CollaborationChannel.GLOBAL,
                f"{user_data['name']} joined the collaboration session",
                MessagePriority.LOW
            )

            await self._save_session(session)
            logger.info(f"Added participant {user_id} to session {session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add participant: {str(e)}")
            return False

    async def send_message(self, session_id: str, sender_id: str, channel: CollaborationChannel,
                          message_type: MessageType, content: str, priority: MessagePriority = MessagePriority.MEDIUM,
                          metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Send a message to a collaboration channel"""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]

            if sender_id not in session.participants:
                return None

            # Check permissions
            if not await self._check_message_permissions(session_id, sender_id, channel, message_type):
                return None

            message_id = f"msg_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            sender_info = session.participants[sender_id]

            message = Message(
                id=message_id,
                sender_id=sender_id,
                sender_name=sender_info["name"],
                channel=channel,
                type=message_type,
                priority=priority,
                content=content,
                timestamp=datetime.now(),
                metadata=metadata or {}
            )

            # Add to channel
            session.channels[channel].append(message)
            session.last_activity = datetime.now()

            # Broadcast to relevant participants
            await self._broadcast_message(session_id, message)

            # Process message through handlers
            await self._process_message_handlers(message)

            await self._save_session(session)
            logger.info(f"Message sent in session {session_id}, channel {channel.value}")
            return message_id

        except Exception as e:
            logger.error(f"Failed to send message: {str(e)}")
            return None

    async def create_thread(self, session_id: str, parent_message_id: str, user_id: str) -> Optional[str]:
        """Create a threaded conversation from a message"""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]
            thread_id = f"thread_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Find parent message
            parent_message = None
            for channel_messages in session.channels.values():
                for msg in channel_messages:
                    if msg.id == parent_message_id:
                        parent_message = msg
                        break
                if parent_message:
                    break

            if not parent_message:
                return None

            # Create thread
            session.active_threads[thread_id] = []

            # Update parent message with thread reference
            parent_message.thread_id = thread_id

            await self._save_session(session)
            logger.info(f"Created thread {thread_id} in session {session_id}")
            return thread_id

        except Exception as e:
            logger.error(f"Failed to create thread: {str(e)}")
            return None

    async def share_artifact(self, session_id: str, user_id: str, artifact_data: Dict[str, Any]) -> Optional[str]:
        """Share an artifact (file, document, tool output) with the team"""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]

            if user_id not in session.participants:
                return None

            artifact_id = f"artifact_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            artifact = SharedArtifact(
                id=artifact_id,
                name=artifact_data["name"],
                type=artifact_data["type"],
                content=artifact_data["content"],
                created_by=user_id,
                created_at=datetime.now(),
                tags=artifact_data.get("tags", []),
                access_level=artifact_data.get("access_level", "team")
            )

            session.shared_artifacts[artifact_id] = artifact

            # Notify about new artifact
            creator_name = session.participants[user_id]["name"]
            notification_msg = await self._create_system_message(
                session_id,
                CollaborationChannel.GLOBAL,
                f"{creator_name} shared artifact: {artifact.name}",
                MessagePriority.MEDIUM,
                {"artifact_id": artifact_id, "artifact_type": artifact.type}
            )

            await self._save_session(session)
            logger.info(f"Shared artifact {artifact_id} in session {session_id}")
            return artifact_id

        except Exception as e:
            logger.error(f"Failed to share artifact: {str(e)}")
            return None

    async def update_real_time_board(self, session_id: str, section: str, data: Any, user_id: str) -> bool:
        """Update the real-time collaboration board"""
        try:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]

            if user_id not in session.participants:
                return False

            # Update board section
            if section not in session.real_time_board:
                session.real_time_board[section] = []

            update_entry = {
                "timestamp": datetime.now().isoformat(),
                "user_id": user_id,
                "user_name": session.participants[user_id]["name"],
                "data": data
            }

            if isinstance(session.real_time_board[section], list):
                session.real_time_board[section].append(update_entry)
            else:
                session.real_time_board[section] = update_entry

            session.last_activity = datetime.now()

            # Broadcast update
            await self._broadcast_board_update(session_id, section, update_entry)

            await self._save_session(session)
            return True

        except Exception as e:
            logger.error(f"Failed to update real-time board: {str(e)}")
            return False

    async def submit_tactical_update(self, session_id: str, user_id: str, update_data: Dict[str, Any]) -> Optional[str]:
        """Submit a tactical update from a team"""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]

            if user_id not in session.participants:
                return None

            update_id = f"tactical_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            tactical_update = TacticalUpdate(
                id=update_id,
                timestamp=datetime.now(),
                team=session.participants[user_id]["team"],
                phase=update_data["phase"],
                status=update_data["status"],
                progress=update_data.get("progress", {}),
                next_actions=update_data.get("next_actions", []),
                blockers=update_data.get("blockers", []),
                key_findings=update_data.get("key_findings", [])
            )

            # Add to real-time board
            await self.update_real_time_board(session_id, "tactical_updates", {
                "update_id": update_id,
                "team": tactical_update.team,
                "phase": tactical_update.phase,
                "status": tactical_update.status,
                "summary": f"{tactical_update.team} - {tactical_update.status}"
            }, user_id)

            # Send tactical briefing message
            briefing_content = f"""Tactical Update from {tactical_update.team}:
Phase: {tactical_update.phase}
Status: {tactical_update.status}
Next Actions: {', '.join(tactical_update.next_actions) if tactical_update.next_actions else 'None'}
Blockers: {', '.join(tactical_update.blockers) if tactical_update.blockers else 'None'}"""

            await self.send_message(
                session_id, user_id, CollaborationChannel.TACTICAL,
                MessageType.TACTICAL_BRIEFING, briefing_content, MessagePriority.HIGH,
                {"tactical_update_id": update_id}
            )

            logger.info(f"Submitted tactical update {update_id} in session {session_id}")
            return update_id

        except Exception as e:
            logger.error(f"Failed to submit tactical update: {str(e)}")
            return None

    async def start_debrief_session(self, session_id: str, facilitator_id: str) -> bool:
        """Start a structured debrief session"""
        try:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]

            # Switch to debrief mode
            debrief_msg = await self._create_system_message(
                session_id,
                CollaborationChannel.DEBRIEF,
                "🎯 Debrief Session Started - All teams can now share lessons learned and insights",
                MessagePriority.HIGH,
                {"facilitator_id": facilitator_id, "debrief_started": True}
            )

            # Enable full collaboration
            session.real_time_board["debrief_mode"] = True
            session.real_time_board["lessons_learned"] = []
            session.real_time_board["improvement_suggestions"] = []

            await self._save_session(session)
            logger.info(f"Started debrief session in {session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to start debrief session: {str(e)}")
            return False

    async def add_reaction(self, session_id: str, message_id: str, user_id: str, reaction: str) -> bool:
        """Add a reaction to a message"""
        try:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]

            # Find message
            message = None
            for channel_messages in session.channels.values():
                for msg in channel_messages:
                    if msg.id == message_id:
                        message = msg
                        break
                if message:
                    break

            if not message:
                return False

            # Add reaction
            if reaction not in message.reactions:
                message.reactions[reaction] = []

            if user_id not in message.reactions[reaction]:
                message.reactions[reaction].append(user_id)

            await self._save_session(session)
            return True

        except Exception as e:
            logger.error(f"Failed to add reaction: {str(e)}")
            return False

    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a collaboration session"""
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        # Calculate activity metrics
        total_messages = sum(len(messages) for messages in session.channels.values())
        active_participants = len([p for p in session.participants.values() if p["status"] == "online"])

        return {
            "session_id": session_id,
            "exercise_id": session.exercise_id,
            "name": session.name,
            "participants_count": len(session.participants),
            "active_participants": active_participants,
            "total_messages": total_messages,
            "shared_artifacts": len(session.shared_artifacts),
            "active_threads": len(session.active_threads),
            "last_activity": session.last_activity.isoformat(),
            "debrief_mode": session.real_time_board.get("debrief_mode", False)
        }

    def get_channel_messages(self, session_id: str, channel: CollaborationChannel,
                           limit: int = 50) -> List[Dict[str, Any]]:
        """Get messages from a specific channel"""
        if session_id not in self.sessions:
            return []

        session = self.sessions[session_id]
        messages = session.channels.get(channel, [])

        # Return latest messages
        latest_messages = messages[-limit:] if len(messages) > limit else messages

        return [
            {
                "id": msg.id,
                "sender_name": msg.sender_name,
                "type": msg.type.value,
                "priority": msg.priority.value,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat(),
                "reactions": dict(msg.reactions),
                "thread_id": msg.thread_id
            }
            for msg in latest_messages
        ]

    async def _check_message_permissions(self, session_id: str, user_id: str,
                                       channel: CollaborationChannel, message_type: MessageType) -> bool:
        """Check if user has permission to send message to channel"""
        session = self.sessions[session_id]
        user_info = session.participants[user_id]

        # Get collaboration rules
        rules = self.collaboration_rules.get("communication_protocols", {})

        # Check team-specific channel access
        user_team = user_info["team"].lower()

        if channel == CollaborationChannel.RED_TEAM and user_team != "red_team":
            return False
        elif channel == CollaborationChannel.BLUE_TEAM and user_team != "blue_team":
            return False
        elif channel == CollaborationChannel.WHITE_TEAM and user_team != "white_team":
            return False

        # Check debrief mode
        if channel == CollaborationChannel.DEBRIEF:
            return session.real_time_board.get("debrief_mode", False)

        return True

    async def _broadcast_message(self, session_id: str, message: Message):
        """Broadcast message to relevant participants"""
        # In a real implementation, this would use WebSockets or similar
        # to push messages to connected clients
        logger.info(f"Broadcasting message {message.id} to channel {message.channel.value}")

    async def _broadcast_board_update(self, session_id: str, section: str, update_data: Dict[str, Any]):
        """Broadcast real-time board updates"""
        logger.info(f"Broadcasting board update for section {section} in session {session_id}")

    async def _create_system_message(self, session_id: str, channel: CollaborationChannel,
                                   content: str, priority: MessagePriority,
                                   metadata: Optional[Dict[str, Any]] = None) -> Message:
        """Create a system-generated message"""
        message_id = f"sys_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

        message = Message(
            id=message_id,
            sender_id="system",
            sender_name="SATRIA System",
            channel=channel,
            type=MessageType.SYSTEM_MESSAGE,
            priority=priority,
            content=content,
            timestamp=datetime.now(),
            metadata=metadata or {}
        )

        session = self.sessions[session_id]
        session.channels[channel].append(message)

        await self._broadcast_message(session_id, message)
        return message

    async def _process_message_handlers(self, message: Message):
        """Process message through registered handlers"""
        handlers = self.message_handlers.get(message.type, [])

        for handler in handlers:
            try:
                await handler(message)
            except Exception as e:
                logger.error(f"Error in message handler: {str(e)}")

    def register_message_handler(self, message_type: MessageType, handler: Callable):
        """Register a handler for specific message types"""
        self.message_handlers[message_type].append(handler)

    async def _save_session(self, session: CollaborationSession):
        """Save collaboration session to storage"""
        file_path = self.data_dir / f"session_{session.id}.json"

        # Convert to serializable format
        session_data = {
            "id": session.id,
            "exercise_id": session.exercise_id,
            "name": session.name,
            "participants": session.participants,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "channels": {
                channel.value: [
                    {
                        "id": msg.id,
                        "sender_id": msg.sender_id,
                        "sender_name": msg.sender_name,
                        "type": msg.type.value,
                        "priority": msg.priority.value,
                        "content": msg.content,
                        "timestamp": msg.timestamp.isoformat(),
                        "metadata": msg.metadata,
                        "thread_id": msg.thread_id,
                        "reactions": dict(msg.reactions)
                    }
                    for msg in messages
                ]
                for channel, messages in session.channels.items()
            },
            "shared_artifacts": {
                aid: {
                    "id": artifact.id,
                    "name": artifact.name,
                    "type": artifact.type,
                    "created_by": artifact.created_by,
                    "created_at": artifact.created_at.isoformat(),
                    "tags": artifact.tags,
                    "access_level": artifact.access_level,
                    "version": artifact.version
                }
                for aid, artifact in session.shared_artifacts.items()
            },
            "real_time_board": session.real_time_board,
            "active_threads": session.active_threads
        }

        with open(file_path, 'w') as f:
            json.dump(session_data, f, indent=2)

# Global instance
collaboration_framework = CollaborationFramework()