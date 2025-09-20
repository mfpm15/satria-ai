"""
SATRIA AI Purple Team Exercise Manager
Coordinates and manages purple team exercises for comprehensive security validation
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ExerciseStatus(Enum):
    PLANNING = "planning"
    SCHEDULED = "scheduled"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class ExerciseType(Enum):
    TABLETOP = "tabletop"
    TECHNICAL = "technical"
    HYBRID = "hybrid"
    CRISIS_SIMULATION = "crisis_simulation"

class TeamRole(Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    WHITE_TEAM = "white_team"
    OBSERVER = "observer"

@dataclass
class ExerciseObjective:
    id: str
    description: str
    success_criteria: List[str]
    weight: float = 1.0
    status: str = "pending"
    completion_percentage: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class TeamMember:
    id: str
    name: str
    role: TeamRole
    skills: List[str]
    contact_info: Dict[str, str]
    availability: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExerciseScenario:
    id: str
    name: str
    description: str
    difficulty_level: int  # 1-10
    estimated_duration: timedelta
    required_skills: List[str]
    attack_vectors: List[str]
    defense_strategies: List[str]
    mitre_tactics: List[str]
    success_metrics: List[str]

@dataclass
class ExerciseSchedule:
    start_time: datetime
    end_time: datetime
    phases: List[Dict[str, Any]]
    checkpoints: List[Dict[str, Any]]
    break_intervals: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class PurpleTeamExercise:
    id: str
    name: str
    type: ExerciseType
    status: ExerciseStatus
    scenario: ExerciseScenario
    objectives: List[ExerciseObjective]
    schedule: ExerciseSchedule
    red_team: List[TeamMember]
    blue_team: List[TeamMember]
    white_team: List[TeamMember]
    observers: List[TeamMember] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_all_participants(self) -> List[TeamMember]:
        return self.red_team + self.blue_team + self.white_team + self.observers

class ExerciseManager:
    def __init__(self, data_dir: str = "data/purple_team"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.exercises: Dict[str, PurpleTeamExercise] = {}
        self.scenarios: Dict[str, ExerciseScenario] = {}
        self.team_members: Dict[str, TeamMember] = {}
        self.active_exercises: Dict[str, Dict[str, Any]] = {}
        self._initialize_default_scenarios()

    def _initialize_default_scenarios(self):
        """Initialize default exercise scenarios"""
        default_scenarios = [
            ExerciseScenario(
                id="phishing_campaign",
                name="Advanced Phishing Campaign",
                description="Simulate sophisticated phishing attack targeting executives",
                difficulty_level=6,
                estimated_duration=timedelta(hours=4),
                required_skills=["social_engineering", "email_security", "incident_response"],
                attack_vectors=["email", "social_media", "phone"],
                defense_strategies=["email_filtering", "user_training", "behavioral_analysis"],
                mitre_tactics=["T1566", "T1204", "T1078"],
                success_metrics=["detection_time", "response_time", "impact_scope"]
            ),
            ExerciseScenario(
                id="apt_simulation",
                name="APT Lateral Movement",
                description="Advanced Persistent Threat with lateral movement simulation",
                difficulty_level=8,
                estimated_duration=timedelta(hours=8),
                required_skills=["penetration_testing", "network_analysis", "malware_analysis"],
                attack_vectors=["network", "endpoints", "credentials"],
                defense_strategies=["network_segmentation", "endpoint_detection", "privilege_management"],
                mitre_tactics=["T1078", "T1021", "T1055", "T1083"],
                success_metrics=["lateral_movement_detection", "data_exfiltration_prevention", "containment_time"]
            ),
            ExerciseScenario(
                id="ransomware_response",
                name="Ransomware Incident Response",
                description="Coordinated ransomware attack and response exercise",
                difficulty_level=7,
                estimated_duration=timedelta(hours=6),
                required_skills=["incident_response", "forensics", "backup_recovery"],
                attack_vectors=["email", "rdp", "vulnerabilities"],
                defense_strategies=["backup_systems", "network_isolation", "endpoint_protection"],
                mitre_tactics=["T1486", "T1490", "T1021.001"],
                success_metrics=["encryption_prevention", "recovery_time", "business_continuity"]
            )
        ]

        for scenario in default_scenarios:
            self.scenarios[scenario.id] = scenario

    async def create_exercise(self, exercise_data: Dict[str, Any]) -> str:
        """Create a new purple team exercise"""
        try:
            exercise_id = f"ex_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Validate scenario
            scenario_id = exercise_data.get("scenario_id")
            if scenario_id not in self.scenarios:
                raise ValueError(f"Scenario {scenario_id} not found")

            scenario = self.scenarios[scenario_id]

            # Create exercise schedule
            start_time = datetime.fromisoformat(exercise_data["start_time"])
            end_time = start_time + scenario.estimated_duration

            schedule = ExerciseSchedule(
                start_time=start_time,
                end_time=end_time,
                phases=exercise_data.get("phases", []),
                checkpoints=exercise_data.get("checkpoints", []),
                break_intervals=exercise_data.get("break_intervals", [])
            )

            # Create objectives
            objectives = []
            for obj_data in exercise_data.get("objectives", []):
                objective = ExerciseObjective(
                    id=obj_data["id"],
                    description=obj_data["description"],
                    success_criteria=obj_data["success_criteria"],
                    weight=obj_data.get("weight", 1.0)
                )
                objectives.append(objective)

            # Assign team members
            red_team = [self.team_members[member_id] for member_id in exercise_data.get("red_team", [])]
            blue_team = [self.team_members[member_id] for member_id in exercise_data.get("blue_team", [])]
            white_team = [self.team_members[member_id] for member_id in exercise_data.get("white_team", [])]
            observers = [self.team_members[member_id] for member_id in exercise_data.get("observers", [])]

            exercise = PurpleTeamExercise(
                id=exercise_id,
                name=exercise_data["name"],
                type=ExerciseType(exercise_data["type"]),
                status=ExerciseStatus.PLANNING,
                scenario=scenario,
                objectives=objectives,
                schedule=schedule,
                red_team=red_team,
                blue_team=blue_team,
                white_team=white_team,
                observers=observers,
                metadata=exercise_data.get("metadata", {})
            )

            self.exercises[exercise_id] = exercise
            await self._save_exercise(exercise)

            logger.info(f"Created purple team exercise: {exercise_id}")
            return exercise_id

        except Exception as e:
            logger.error(f"Failed to create exercise: {str(e)}")
            raise

    async def start_exercise(self, exercise_id: str) -> bool:
        """Start a purple team exercise"""
        try:
            if exercise_id not in self.exercises:
                raise ValueError(f"Exercise {exercise_id} not found")

            exercise = self.exercises[exercise_id]

            if exercise.status != ExerciseStatus.SCHEDULED:
                raise ValueError(f"Exercise {exercise_id} is not in scheduled state")

            # Initialize exercise session
            exercise.status = ExerciseStatus.ACTIVE
            exercise.updated_at = datetime.now()

            session_data = {
                "start_time": datetime.now().isoformat(),
                "current_phase": 0,
                "phase_logs": [],
                "team_communications": [],
                "real_time_metrics": {},
                "incident_timeline": []
            }

            self.active_exercises[exercise_id] = session_data

            # Notify all participants
            await self._notify_participants(exercise, "Exercise Started",
                                          f"Purple team exercise '{exercise.name}' has begun")

            # Start monitoring
            asyncio.create_task(self._monitor_exercise(exercise_id))

            await self._save_exercise(exercise)
            logger.info(f"Started purple team exercise: {exercise_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to start exercise {exercise_id}: {str(e)}")
            return False

    async def pause_exercise(self, exercise_id: str) -> bool:
        """Pause an active exercise"""
        try:
            if exercise_id not in self.exercises:
                return False

            exercise = self.exercises[exercise_id]
            if exercise.status != ExerciseStatus.ACTIVE:
                return False

            exercise.status = ExerciseStatus.PAUSED
            exercise.updated_at = datetime.now()

            if exercise_id in self.active_exercises:
                self.active_exercises[exercise_id]["paused_at"] = datetime.now().isoformat()

            await self._notify_participants(exercise, "Exercise Paused",
                                          f"Purple team exercise '{exercise.name}' has been paused")

            await self._save_exercise(exercise)
            logger.info(f"Paused purple team exercise: {exercise_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to pause exercise {exercise_id}: {str(e)}")
            return False

    async def complete_exercise(self, exercise_id: str) -> Dict[str, Any]:
        """Complete an exercise and generate final report"""
        try:
            if exercise_id not in self.exercises:
                raise ValueError(f"Exercise {exercise_id} not found")

            exercise = self.exercises[exercise_id]
            exercise.status = ExerciseStatus.COMPLETED
            exercise.updated_at = datetime.now()

            # Calculate final metrics
            completion_report = await self._generate_completion_report(exercise_id)

            # Clean up active session
            if exercise_id in self.active_exercises:
                del self.active_exercises[exercise_id]

            await self._notify_participants(exercise, "Exercise Completed",
                                          f"Purple team exercise '{exercise.name}' has been completed")

            await self._save_exercise(exercise)
            logger.info(f"Completed purple team exercise: {exercise_id}")

            return completion_report

        except Exception as e:
            logger.error(f"Failed to complete exercise {exercise_id}: {str(e)}")
            raise

    async def update_objective_progress(self, exercise_id: str, objective_id: str,
                                      progress: float, evidence: Dict[str, Any]) -> bool:
        """Update progress on an exercise objective"""
        try:
            if exercise_id not in self.exercises:
                return False

            exercise = self.exercises[exercise_id]

            for objective in exercise.objectives:
                if objective.id == objective_id:
                    objective.completion_percentage = min(100.0, max(0.0, progress))
                    objective.evidence.append({
                        "timestamp": datetime.now().isoformat(),
                        "data": evidence
                    })

                    if objective.completion_percentage >= 100.0:
                        objective.status = "completed"
                    elif objective.completion_percentage > 0:
                        objective.status = "in_progress"

                    exercise.updated_at = datetime.now()
                    await self._save_exercise(exercise)

                    # Update real-time metrics
                    if exercise_id in self.active_exercises:
                        self._update_real_time_metrics(exercise_id)

                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to update objective progress: {str(e)}")
            return False

    async def add_team_member(self, member_data: Dict[str, Any]) -> str:
        """Add a team member to the pool"""
        try:
            member_id = f"tm_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            member = TeamMember(
                id=member_id,
                name=member_data["name"],
                role=TeamRole(member_data["role"]),
                skills=member_data["skills"],
                contact_info=member_data["contact_info"],
                availability=member_data.get("availability", {})
            )

            self.team_members[member_id] = member
            await self._save_team_member(member)

            logger.info(f"Added team member: {member_id}")
            return member_id

        except Exception as e:
            logger.error(f"Failed to add team member: {str(e)}")
            raise

    def get_exercise_status(self, exercise_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of an exercise"""
        if exercise_id not in self.exercises:
            return None

        exercise = self.exercises[exercise_id]

        # Calculate overall progress
        total_weight = sum(obj.weight for obj in exercise.objectives)
        completed_weight = sum(obj.weight * (obj.completion_percentage / 100.0)
                             for obj in exercise.objectives)
        overall_progress = (completed_weight / total_weight * 100.0) if total_weight > 0 else 0.0

        status = {
            "exercise_id": exercise_id,
            "name": exercise.name,
            "status": exercise.status.value,
            "type": exercise.type.value,
            "overall_progress": overall_progress,
            "start_time": exercise.schedule.start_time.isoformat(),
            "end_time": exercise.schedule.end_time.isoformat(),
            "participants_count": len(exercise.get_all_participants()),
            "objectives": [
                {
                    "id": obj.id,
                    "description": obj.description,
                    "progress": obj.completion_percentage,
                    "status": obj.status
                }
                for obj in exercise.objectives
            ],
            "real_time_data": self.active_exercises.get(exercise_id, {})
        }

        return status

    def list_exercises(self, status_filter: Optional[ExerciseStatus] = None) -> List[Dict[str, Any]]:
        """List all exercises with optional status filtering"""
        exercises = []

        for exercise in self.exercises.values():
            if status_filter is None or exercise.status == status_filter:
                exercises.append({
                    "id": exercise.id,
                    "name": exercise.name,
                    "type": exercise.type.value,
                    "status": exercise.status.value,
                    "created_at": exercise.created_at.isoformat(),
                    "participants": len(exercise.get_all_participants())
                })

        return sorted(exercises, key=lambda x: x["created_at"], reverse=True)

    async def _monitor_exercise(self, exercise_id: str):
        """Monitor exercise progress and handle automated events"""
        try:
            while exercise_id in self.active_exercises:
                exercise = self.exercises[exercise_id]

                if exercise.status == ExerciseStatus.COMPLETED:
                    break

                # Update real-time metrics
                self._update_real_time_metrics(exercise_id)

                # Check for scheduled events
                await self._process_scheduled_events(exercise_id)

                # Auto-complete if time exceeded
                if datetime.now() > exercise.schedule.end_time:
                    await self.complete_exercise(exercise_id)
                    break

                await asyncio.sleep(30)  # Check every 30 seconds

        except Exception as e:
            logger.error(f"Error monitoring exercise {exercise_id}: {str(e)}")

    def _update_real_time_metrics(self, exercise_id: str):
        """Update real-time exercise metrics"""
        if exercise_id not in self.active_exercises:
            return

        exercise = self.exercises[exercise_id]
        session = self.active_exercises[exercise_id]

        # Calculate metrics
        total_objectives = len(exercise.objectives)
        completed_objectives = sum(1 for obj in exercise.objectives if obj.status == "completed")
        avg_progress = sum(obj.completion_percentage for obj in exercise.objectives) / total_objectives if total_objectives > 0 else 0

        elapsed_time = datetime.now() - datetime.fromisoformat(session["start_time"])

        session["real_time_metrics"] = {
            "elapsed_time_minutes": elapsed_time.total_seconds() / 60,
            "completed_objectives": completed_objectives,
            "total_objectives": total_objectives,
            "average_progress": avg_progress,
            "active_participants": len(exercise.get_all_participants()),
            "last_updated": datetime.now().isoformat()
        }

    async def _process_scheduled_events(self, exercise_id: str):
        """Process any scheduled events for the exercise"""
        # Implementation for handling scheduled events like phase transitions,
        # automated injections, etc.
        pass

    async def _generate_completion_report(self, exercise_id: str) -> Dict[str, Any]:
        """Generate comprehensive completion report"""
        exercise = self.exercises[exercise_id]
        session_data = self.active_exercises.get(exercise_id, {})

        # Calculate final metrics
        total_objectives = len(exercise.objectives)
        completed_objectives = sum(1 for obj in exercise.objectives if obj.status == "completed")
        completion_rate = (completed_objectives / total_objectives * 100.0) if total_objectives > 0 else 0.0

        start_time = datetime.fromisoformat(session_data.get("start_time", datetime.now().isoformat()))
        total_duration = datetime.now() - start_time

        report = {
            "exercise_id": exercise_id,
            "exercise_name": exercise.name,
            "completion_date": datetime.now().isoformat(),
            "duration": {
                "total_minutes": total_duration.total_seconds() / 60,
                "scheduled_minutes": exercise.scenario.estimated_duration.total_seconds() / 60
            },
            "objectives": {
                "total": total_objectives,
                "completed": completed_objectives,
                "completion_rate": completion_rate,
                "details": [
                    {
                        "id": obj.id,
                        "description": obj.description,
                        "completion_percentage": obj.completion_percentage,
                        "evidence_count": len(obj.evidence)
                    }
                    for obj in exercise.objectives
                ]
            },
            "participants": {
                "red_team": len(exercise.red_team),
                "blue_team": len(exercise.blue_team),
                "white_team": len(exercise.white_team),
                "observers": len(exercise.observers)
            },
            "scenario_performance": {
                "difficulty_level": exercise.scenario.difficulty_level,
                "attack_vectors_tested": exercise.scenario.attack_vectors,
                "mitre_tactics_covered": exercise.scenario.mitre_tactics
            }
        }

        return report

    async def _notify_participants(self, exercise: PurpleTeamExercise, subject: str, message: str):
        """Send notifications to all exercise participants"""
        participants = exercise.get_all_participants()

        for participant in participants:
            # In a real implementation, this would send actual notifications
            # via email, Slack, Teams, etc.
            logger.info(f"Notification to {participant.name}: {subject} - {message}")

    async def _save_exercise(self, exercise: PurpleTeamExercise):
        """Save exercise data to storage"""
        file_path = self.data_dir / f"exercise_{exercise.id}.json"

        # Convert to serializable format
        exercise_data = {
            "id": exercise.id,
            "name": exercise.name,
            "type": exercise.type.value,
            "status": exercise.status.value,
            "created_at": exercise.created_at.isoformat(),
            "updated_at": exercise.updated_at.isoformat(),
            "scenario": {
                "id": exercise.scenario.id,
                "name": exercise.scenario.name,
                "description": exercise.scenario.description,
                "difficulty_level": exercise.scenario.difficulty_level,
                "estimated_duration": exercise.scenario.estimated_duration.total_seconds(),
                "required_skills": exercise.scenario.required_skills,
                "attack_vectors": exercise.scenario.attack_vectors,
                "defense_strategies": exercise.scenario.defense_strategies,
                "mitre_tactics": exercise.scenario.mitre_tactics,
                "success_metrics": exercise.scenario.success_metrics
            },
            "objectives": [
                {
                    "id": obj.id,
                    "description": obj.description,
                    "success_criteria": obj.success_criteria,
                    "weight": obj.weight,
                    "status": obj.status,
                    "completion_percentage": obj.completion_percentage,
                    "evidence": obj.evidence
                }
                for obj in exercise.objectives
            ],
            "schedule": {
                "start_time": exercise.schedule.start_time.isoformat(),
                "end_time": exercise.schedule.end_time.isoformat(),
                "phases": exercise.schedule.phases,
                "checkpoints": exercise.schedule.checkpoints,
                "break_intervals": exercise.schedule.break_intervals
            },
            "teams": {
                "red_team": [member.id for member in exercise.red_team],
                "blue_team": [member.id for member in exercise.blue_team],
                "white_team": [member.id for member in exercise.white_team],
                "observers": [member.id for member in exercise.observers]
            },
            "metadata": exercise.metadata
        }

        with open(file_path, 'w') as f:
            json.dump(exercise_data, f, indent=2)

    async def _save_team_member(self, member: TeamMember):
        """Save team member data to storage"""
        file_path = self.data_dir / f"member_{member.id}.json"

        member_data = {
            "id": member.id,
            "name": member.name,
            "role": member.role.value,
            "skills": member.skills,
            "contact_info": member.contact_info,
            "availability": member.availability
        }

        with open(file_path, 'w') as f:
            json.dump(member_data, f, indent=2)

# Global instance
exercise_manager = ExerciseManager()