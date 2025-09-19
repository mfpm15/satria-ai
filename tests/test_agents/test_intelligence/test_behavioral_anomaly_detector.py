"""
Unit tests for Behavioral Anomaly Detector Agent
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from satria.agents.intelligence.behavioral_anomaly_detector import BehavioralAnomalyDetector
from satria.models.events import BaseEvent, EventCategory, EventClass


@pytest.fixture
def detector():
    """Create a behavioral anomaly detector instance for testing"""
    return BehavioralAnomalyDetector()


@pytest.fixture
def sample_auth_event():
    """Create a sample authentication event"""
    return BaseEvent(
        event_type="authentication_success",
        event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
        event_class=EventClass.AUTHENTICATION,
        timestamp=datetime.now(timezone.utc),
        entity_ids={"user": "john.doe@company.com", "host": "WORKSTATION-01"},
        message="Successful login",
        enrichment={
            "source_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0",
            "session_id": "sess_123"
        }
    )


@pytest.fixture
def sample_process_event():
    """Create a sample process event"""
    return BaseEvent(
        event_type="process_creation",
        event_category=EventCategory.SYSTEM_ACTIVITY,
        event_class=EventClass.PROCESS_ACTIVITY,
        timestamp=datetime.now(timezone.utc),
        entity_ids={"host": "SERVER-01", "process": "powershell.exe"},
        message="Process creation",
        enrichment={
            "command_line": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwB1AHMAcABpAGMAaQBvAHUAcwAiAA==",
            "parent_process": "cmd.exe",
            "user": "SYSTEM"
        }
    )


class TestBehavioralAnomalyDetector:
    """Test cases for Behavioral Anomaly Detector"""

    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test agent initialization"""
        result = await detector.initialize()
        assert result is True
        assert detector.models is not None
        assert len(detector.behavioral_profiles) >= 0

    @pytest.mark.asyncio
    async def test_process_authentication_event(self, detector, sample_auth_event):
        """Test processing authentication events"""
        await detector.initialize()

        result = await detector.process_event(sample_auth_event)
        assert isinstance(result, list)
        assert len(result) == 1

        processed_event = result[0]
        assert processed_event.event_id == sample_auth_event.event_id
        assert "behavioral_analysis" in processed_event.enrichment

    @pytest.mark.asyncio
    async def test_process_suspicious_process_event(self, detector, sample_process_event):
        """Test processing suspicious process events"""
        await detector.initialize()

        result = await detector.process_event(sample_process_event)
        assert isinstance(result, list)
        assert len(result) == 1

        processed_event = result[0]
        assert "behavioral_analysis" in processed_event.enrichment

        # Should detect suspicious PowerShell command
        analysis = processed_event.enrichment["behavioral_analysis"]
        assert analysis["anomaly_score"] > 0

    @pytest.mark.asyncio
    async def test_off_hours_login_detection(self, detector):
        """Test detection of off-hours login attempts"""
        await detector.initialize()

        # Create event with off-hours timestamp (2 AM)
        off_hours_event = BaseEvent(
            event_type="authentication_success",
            event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
            event_class=EventClass.AUTHENTICATION,
            timestamp=datetime(2025, 1, 15, 2, 0, 0, tzinfo=timezone.utc),  # 2 AM
            entity_ids={"user": "admin@company.com"},
            message="Off-hours login"
        )

        result = await detector.process_event(off_hours_event)
        processed_event = result[0]

        analysis = processed_event.enrichment["behavioral_analysis"]
        assert analysis["temporal_anomaly"] > 0

    @pytest.mark.asyncio
    async def test_user_profile_building(self, detector, sample_auth_event):
        """Test user behavioral profile building"""
        await detector.initialize()

        user_id = sample_auth_event.entity_ids["user"]

        # Process multiple events to build profile
        for _ in range(5):
            await detector.process_event(sample_auth_event)

        # Check if profile was created
        assert user_id in detector.behavioral_profiles
        profile = detector.behavioral_profiles[user_id]
        assert profile["login_count"] >= 5

    @pytest.mark.asyncio
    async def test_frequency_anomaly_detection(self, detector):
        """Test detection of high-frequency anomalies"""
        await detector.initialize()

        # Simulate rapid authentication attempts
        user_id = "test.user@company.com"
        auth_event = BaseEvent(
            event_type="authentication_failure",
            event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
            event_class=EventClass.AUTHENTICATION,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"user": user_id},
            message="Failed login attempt"
        )

        # Process many failed attempts
        results = []
        for _ in range(20):
            result = await detector.process_event(auth_event)
            results.extend(result)

        # Should detect frequency anomaly
        last_result = results[-1]
        analysis = last_result.enrichment["behavioral_analysis"]
        assert analysis["frequency_score"] > 50  # High frequency score

    @pytest.mark.asyncio
    async def test_ml_model_prediction(self, detector):
        """Test ML model predictions"""
        await detector.initialize()

        # Mock ML model behavior
        with patch.object(detector.models["isolation_forest"], "predict", return_value=[-1]):  # Anomaly
            with patch.object(detector.models["isolation_forest"], "decision_function", return_value=[-0.5]):

                event = BaseEvent(
                    event_type="file_access",
                    event_category=EventCategory.SYSTEM_ACTIVITY,
                    event_class=EventClass.FILE_SYSTEM_ACTIVITY,
                    timestamp=datetime.now(timezone.utc),
                    entity_ids={"user": "suspicious.user@company.com"},
                    message="File access"
                )

                result = await detector.process_event(event)
                processed_event = result[0]

                analysis = processed_event.enrichment["behavioral_analysis"]
                assert "ml_anomaly_score" in analysis

    @pytest.mark.asyncio
    async def test_cleanup(self, detector):
        """Test agent cleanup"""
        await detector.initialize()

        # Add some test data
        detector.behavioral_profiles["test_user"] = {"login_count": 5}
        assert len(detector.behavioral_profiles) > 0

        # Test cleanup
        await detector.cleanup()
        assert len(detector.behavioral_profiles) == 0

    @pytest.mark.asyncio
    async def test_metrics(self, detector):
        """Test metrics collection"""
        await detector.initialize()

        # Process some events
        event = BaseEvent(
            event_type="test_event",
            event_category=EventCategory.SYSTEM_ACTIVITY,
            event_class=EventClass.PROCESS_ACTIVITY,
            timestamp=datetime.now(timezone.utc),
            entity_ids={"test": "data"},
            message="Test event"
        )

        await detector.process_event(event)

        metrics = detector.get_metrics()
        assert "events_processed" in metrics
        assert "behavioral_profiles" in metrics
        assert "anomalies_detected" in metrics
        assert metrics["events_processed"] >= 1

    @pytest.mark.asyncio
    async def test_suspicious_process_patterns(self, detector):
        """Test detection of suspicious process patterns"""
        await detector.initialize()

        suspicious_commands = [
            "powershell.exe -enc base64encodedcommand",
            "cmd.exe /c ping google.com",
            "wscript.exe malicious.vbs",
            "regsvr32.exe /s /u scrobj.dll"
        ]

        for cmd in suspicious_commands:
            event = BaseEvent(
                event_type="process_creation",
                event_category=EventCategory.SYSTEM_ACTIVITY,
                event_class=EventClass.PROCESS_ACTIVITY,
                timestamp=datetime.now(timezone.utc),
                entity_ids={"host": "TEST-HOST"},
                message="Process creation",
                enrichment={"command_line": cmd}
            )

            result = await detector.process_event(event)
            processed_event = result[0]

            analysis = processed_event.enrichment["behavioral_analysis"]
            # Should detect all these as suspicious
            assert analysis["anomaly_score"] > 30

    @pytest.mark.asyncio
    async def test_error_handling(self, detector):
        """Test error handling in processing"""
        await detector.initialize()

        # Create malformed event
        malformed_event = BaseEvent(
            event_type="test_event",
            event_category=EventCategory.SYSTEM_ACTIVITY,
            event_class=EventClass.PROCESS_ACTIVITY,
            timestamp=datetime.now(timezone.utc),
            entity_ids=None,  # This might cause issues
            message="Test event"
        )

        # Should handle gracefully without crashing
        result = await detector.process_event(malformed_event)
        assert isinstance(result, list)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_concurrent_processing(self, detector):
        """Test concurrent event processing"""
        await detector.initialize()

        events = []
        for i in range(10):
            event = BaseEvent(
                event_type="test_event",
                event_category=EventCategory.SYSTEM_ACTIVITY,
                event_class=EventClass.PROCESS_ACTIVITY,
                timestamp=datetime.now(timezone.utc),
                entity_ids={"user": f"user{i}@company.com"},
                message=f"Test event {i}"
            )
            events.append(event)

        # Process events concurrently
        tasks = [detector.process_event(event) for event in events]
        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        for result in results:
            assert isinstance(result, list)
            assert len(result) == 1


@pytest.mark.asyncio
async def test_integration_scenario():
    """Test a realistic integration scenario"""
    detector = BehavioralAnomalyDetector()
    await detector.initialize()

    # Scenario: User shows normal behavior, then suspicious activity
    user_id = "alice.smith@company.com"

    # Normal working hours logins
    normal_events = []
    for hour in [9, 10, 14, 16]:  # Normal working hours
        event = BaseEvent(
            event_type="authentication_success",
            event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
            event_class=EventClass.AUTHENTICATION,
            timestamp=datetime(2025, 1, 15, hour, 0, 0, tzinfo=timezone.utc),
            entity_ids={"user": user_id, "host": "WORKSTATION-01"},
            message="Normal login"
        )
        normal_events.append(event)

    # Process normal events
    for event in normal_events:
        await detector.process_event(event)

    # Now suspicious late-night activity
    suspicious_event = BaseEvent(
        event_type="authentication_success",
        event_category=EventCategory.IDENTITY_ACCESS_MANAGEMENT,
        event_class=EventClass.AUTHENTICATION,
        timestamp=datetime(2025, 1, 15, 23, 30, 0, tzinfo=timezone.utc),  # 11:30 PM
        entity_ids={"user": user_id, "host": "UNKNOWN-HOST"},
        message="Late night login from unknown host",
        enrichment={"source_ip": "10.0.0.100"}  # Different IP
    )

    result = await detector.process_event(suspicious_event)
    processed_event = result[0]

    analysis = processed_event.enrichment["behavioral_analysis"]

    # Should detect temporal and location anomalies
    assert analysis["temporal_anomaly"] > 0
    assert analysis["anomaly_score"] > 40  # Should be flagged as suspicious

    await detector.cleanup()


if __name__ == "__main__":
    pytest.main([__file__])