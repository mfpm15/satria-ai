"""
Tests for SATRIA AI Enterprise Purple Team Module
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from satria.enterprise.purple_team.validation_engine import (
    PurpleTeamValidator,
    AttackScenario,
    ValidationTest,
    TestResult,
    AttackVector
)
from satria.enterprise.purple_team.exercise_manager import (
    ExerciseManager,
    ExerciseStatus,
    ExerciseType,
    TeamRole
)


class TestPurpleTeamValidator:
    """Test purple team validation functionality"""

    @pytest.fixture
    def validator(self):
        """Create a test purple team validator instance"""
        return PurpleTeamValidator()

    def test_validator_initialization(self, validator):
        """Test validator initializes correctly"""
        assert validator is not None
        assert hasattr(validator, 'scenarios')
        assert hasattr(validator, 'validation_tests')
        assert hasattr(validator, 'test_results')

    def test_attack_scenario_creation(self):
        """Test attack scenario creation"""
        scenario = AttackScenario(
            id="test-scenario-001",
            name="Test Phishing Attack",
            description="Test phishing scenario",
            attack_vectors=[AttackVector.EMAIL],
            mitre_tactics=["T1566"],
            difficulty_level=5,
            estimated_duration=timedelta(hours=2)
        )

        assert scenario.id == "test-scenario-001"
        assert scenario.name == "Test Phishing Attack"
        assert AttackVector.EMAIL in scenario.attack_vectors
        assert "T1566" in scenario.mitre_tactics

    def test_validation_test_creation(self):
        """Test validation test creation"""
        test = ValidationTest(
            id="test-validation-001",
            scenario_id="test-scenario-001",
            name="Email Detection Test",
            description="Test email detection capabilities",
            test_type="detection",
            expected_outcomes=["alert_generated", "email_blocked"]
        )

        assert test.id == "test-validation-001"
        assert test.scenario_id == "test-scenario-001"
        assert test.test_type == "detection"

    @pytest.mark.asyncio
    async def test_run_validation(self, validator):
        """Test running validation tests"""
        with patch.object(validator, '_execute_test') as mock_execute:
            mock_execute.return_value = TestResult(
                test_id="test-validation-001",
                status="passed",
                score=85.0,
                details={"detection_time": 30},
                evidence=[]
            )

            result = await validator.run_validation("test-validation-001")

            assert result.test_id == "test-validation-001"
            assert result.status == "passed"
            assert result.score == 85.0
            mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_scenario_execution(self, validator):
        """Test executing attack scenarios"""
        scenario_data = {
            "id": "test-scenario-001",
            "name": "Test Attack",
            "attack_vectors": ["email"],
            "validation_tests": ["test-validation-001"]
        }

        with patch.object(validator, 'run_validation') as mock_validation:
            mock_validation.return_value = TestResult(
                test_id="test-validation-001",
                status="passed",
                score=90.0,
                details={},
                evidence=[]
            )

            result = await validator.execute_scenario(scenario_data)

            assert "scenario_id" in result
            assert result["overall_score"] >= 0
            mock_validation.assert_called()

    def test_get_status(self, validator):
        """Test getting validator status"""
        status = validator.get_status()

        assert 'available_scenarios' in status
        assert 'active_validations' in status
        assert 'validation_history' in status
        assert isinstance(status['available_scenarios'], list)


class TestExerciseManager:
    """Test exercise manager functionality"""

    @pytest.fixture
    def exercise_manager(self):
        """Create a test exercise manager instance"""
        return ExerciseManager()

    def test_exercise_manager_initialization(self, exercise_manager):
        """Test exercise manager initializes correctly"""
        assert exercise_manager is not None
        assert hasattr(exercise_manager, 'exercises')
        assert hasattr(exercise_manager, 'scenarios')
        assert hasattr(exercise_manager, 'team_members')

    @pytest.mark.asyncio
    async def test_create_exercise(self, exercise_manager):
        """Test creating a new exercise"""
        exercise_data = {
            "name": "Test Purple Team Exercise",
            "type": "technical",
            "scenario_id": "phishing_campaign",
            "start_time": (datetime.now() + timedelta(hours=1)).isoformat(),
            "objectives": [
                {
                    "id": "obj-001",
                    "description": "Detect phishing email",
                    "success_criteria": ["Email detected within 30 seconds"]
                }
            ],
            "red_team": [],
            "blue_team": [],
            "white_team": []
        }

        with patch.object(exercise_manager, '_save_exercise', new_callable=AsyncMock):
            exercise_id = await exercise_manager.create_exercise(exercise_data)

            assert exercise_id is not None
            assert exercise_id.startswith("ex_")
            assert exercise_id in exercise_manager.exercises

    @pytest.mark.asyncio
    async def test_exercise_lifecycle(self, exercise_manager):
        """Test exercise start, pause, and complete lifecycle"""
        # Create exercise first
        exercise_data = {
            "name": "Lifecycle Test Exercise",
            "type": "technical",
            "scenario_id": "phishing_campaign",
            "start_time": datetime.now().isoformat(),
            "objectives": [],
            "red_team": [],
            "blue_team": [],
            "white_team": []
        }

        with patch.object(exercise_manager, '_save_exercise', new_callable=AsyncMock), \
             patch.object(exercise_manager, '_notify_participants', new_callable=AsyncMock), \
             patch.object(exercise_manager, '_monitor_exercise', new_callable=AsyncMock):

            exercise_id = await exercise_manager.create_exercise(exercise_data)

            # Update status to scheduled for testing
            exercise_manager.exercises[exercise_id].status = ExerciseStatus.SCHEDULED

            # Test start
            result = await exercise_manager.start_exercise(exercise_id)
            assert result is True
            assert exercise_manager.exercises[exercise_id].status == ExerciseStatus.ACTIVE

            # Test pause
            result = await exercise_manager.pause_exercise(exercise_id)
            assert result is True
            assert exercise_manager.exercises[exercise_id].status == ExerciseStatus.PAUSED

    @pytest.mark.asyncio
    async def test_add_team_member(self, exercise_manager):
        """Test adding team members"""
        member_data = {
            "name": "Test Member",
            "role": "red_team",
            "skills": ["penetration_testing", "social_engineering"],
            "contact_info": {"email": "test@example.com"}
        }

        with patch.object(exercise_manager, '_save_team_member', new_callable=AsyncMock):
            member_id = await exercise_manager.add_team_member(member_data)

            assert member_id is not None
            assert member_id.startswith("tm_")
            assert member_id in exercise_manager.team_members

    def test_get_exercise_status(self, exercise_manager):
        """Test getting exercise status"""
        # Create a mock exercise
        from satria.enterprise.purple_team.exercise_manager import (
            PurpleTeamExercise, ExerciseScenario, ExerciseSchedule, ExerciseObjective
        )

        scenario = ExerciseScenario(
            id="test-scenario",
            name="Test Scenario",
            description="Test",
            difficulty_level=5,
            estimated_duration=timedelta(hours=2),
            required_skills=[],
            attack_vectors=[],
            defense_strategies=[],
            mitre_tactics=[],
            success_metrics=[]
        )

        schedule = ExerciseSchedule(
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(hours=2),
            phases=[],
            checkpoints=[]
        )

        objective = ExerciseObjective(
            id="obj-001",
            description="Test objective",
            success_criteria=["Test criteria"],
            completion_percentage=50.0
        )

        exercise = PurpleTeamExercise(
            id="test-exercise",
            name="Test Exercise",
            type=ExerciseType.TECHNICAL,
            status=ExerciseStatus.ACTIVE,
            scenario=scenario,
            objectives=[objective],
            schedule=schedule,
            red_team=[],
            blue_team=[],
            white_team=[]
        )

        exercise_manager.exercises["test-exercise"] = exercise

        status = exercise_manager.get_exercise_status("test-exercise")

        assert status is not None
        assert status["exercise_id"] == "test-exercise"
        assert status["status"] == ExerciseStatus.ACTIVE.value
        assert status["overall_progress"] == 50.0

    def test_list_exercises(self, exercise_manager):
        """Test listing exercises"""
        exercises = exercise_manager.list_exercises()
        assert isinstance(exercises, list)

        # Test with status filter
        exercises_active = exercise_manager.list_exercises(ExerciseStatus.ACTIVE)
        assert isinstance(exercises_active, list)


@pytest.mark.integration
class TestPurpleTeamIntegration:
    """Integration tests for purple team module"""

    @pytest.mark.asyncio
    async def test_full_purple_team_workflow(self):
        """Test complete purple team workflow"""
        validator = PurpleTeamValidator()
        exercise_manager = ExerciseManager()

        # Initialize components
        validator.initialize()

        # Test status checks
        validator_status = validator.get_status()
        assert isinstance(validator_status, dict)

        # Test exercise manager
        exercises = exercise_manager.list_exercises()
        assert isinstance(exercises, list)

    @pytest.mark.asyncio
    async def test_scenario_validation_integration(self):
        """Test scenario and validation integration"""
        validator = PurpleTeamValidator()

        # Mock scenario execution
        with patch.object(validator, '_execute_test') as mock_execute:
            mock_execute.return_value = TestResult(
                test_id="integration-test",
                status="passed",
                score=95.0,
                details={"integration": True},
                evidence=[]
            )

            # Test scenario with validation
            scenario_data = {
                "id": "integration-scenario",
                "name": "Integration Test Scenario",
                "attack_vectors": ["network"],
                "validation_tests": ["integration-test"]
            }

            result = await validator.execute_scenario(scenario_data)

            assert result["scenario_id"] == "integration-scenario"
            assert result["overall_score"] >= 0