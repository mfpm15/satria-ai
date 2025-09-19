"""
Unit tests for Analyst Copilot Agent
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from satria.agents.copilot.analyst_copilot import AnalystCopilot
from satria.models.events import BaseEvent, EventCategory, EventClass


@pytest.fixture
def copilot():
    """Create an analyst copilot instance for testing"""
    return AnalystCopilot()


@pytest.fixture
def sample_query():
    """Create a sample security query"""
    return {
        "query": "What are the best indicators for detecting APT29?",
        "query_type": "threat_analysis",
        "context": {"severity": "high"},
        "session_id": "test_session_123"
    }


@pytest.fixture
def sample_event():
    """Create a sample security event"""
    return BaseEvent(
        event_type="malware_detection",
        event_category=EventCategory.FINDINGS,
        event_class=EventClass.DETECTION_FINDING,
        timestamp=datetime.now(timezone.utc),
        entity_ids={"host": "WORKSTATION-01", "file": "suspicious.exe"},
        message="Malware detected",
        risk=85,
        enrichment={
            "file_hash": "a1b2c3d4e5f6",
            "detection_engine": "Windows Defender",
            "threat_name": "Trojan.Generic"
        }
    )


class TestAnalystCopilot:
    """Test cases for Analyst Copilot"""

    @pytest.mark.asyncio
    async def test_initialization(self, copilot):
        """Test agent initialization"""
        result = await copilot.initialize()
        assert result is True
        assert copilot.knowledge_base is not None
        assert len(copilot.active_sessions) == 0

    @pytest.mark.asyncio
    async def test_session_management(self, copilot):
        """Test session creation and management"""
        await copilot.initialize()

        # Create session
        session_id = await copilot.create_session("analyst_123", {
            "response_format": "technical_details",
            "include_mitre_mapping": True
        })

        assert session_id is not None
        assert session_id in copilot.active_sessions
        assert copilot.active_sessions[session_id]["analyst_id"] == "analyst_123"

        # End session
        await copilot.end_session(session_id)
        assert session_id not in copilot.active_sessions

    @pytest.mark.asyncio
    async def test_query_processing(self, copilot, sample_query):
        """Test query processing"""
        await copilot.initialize()

        response = await copilot.process_query(sample_query)

        assert response is not None
        assert "query_id" in response
        assert "response" in response
        assert "confidence" in response["response"]
        assert "recommendations" in response["response"]
        assert "processing_time" in response

        # Check response quality
        assert isinstance(response["response"]["recommendations"], list)
        assert len(response["response"]["recommendations"]) > 0
        assert response["response"]["confidence"] > 0

    @pytest.mark.asyncio
    async def test_threat_analysis_query(self, copilot):
        """Test threat analysis specific queries"""
        await copilot.initialize()

        apt_query = {
            "query": "How do I detect lateral movement in my network?",
            "query_type": "threat_analysis",
            "context": {"incident_id": "INC-2025-001"}
        }

        response = await copilot.process_query(apt_query)

        assert "lateral movement" in response["response"]["text"].lower()
        assert len(response["response"]["recommendations"]) > 0

        # Should include MITRE ATT&CK references
        supporting_evidence = response["response"]["supporting_evidence"]
        assert any("MITRE" in evidence for evidence in supporting_evidence)

    @pytest.mark.asyncio
    async def test_incident_response_query(self, copilot):
        """Test incident response queries"""
        await copilot.initialize()

        ir_query = {
            "query": "I have a ransomware incident. What are the immediate steps?",
            "query_type": "incident_response",
            "context": {"severity": "critical", "affected_systems": 50}
        }

        response = await copilot.process_query(ir_query)

        # Should provide actionable recommendations
        recommendations = response["response"]["recommendations"]
        assert len(recommendations) >= 3

        # Should mention isolation, backup, etc.
        text = response["response"]["text"].lower()
        assert any(keyword in text for keyword in ["isolate", "contain", "backup", "recovery"])

    @pytest.mark.asyncio
    async def test_ioc_analysis_query(self, copilot):
        """Test IOC analysis queries"""
        await copilot.initialize()

        ioc_query = {
            "query": "Analyze this suspicious IP: 185.220.101.182",
            "query_type": "ioc_analysis",
            "indicators": ["185.220.101.182"]
        }

        response = await copilot.process_query(ioc_query)

        # Should provide analysis of the IP
        text = response["response"]["text"]
        assert "185.220.101.182" in text

        # Should provide follow-up questions
        follow_ups = response["response"]["follow_up_questions"]
        assert len(follow_ups) > 0

    @pytest.mark.asyncio
    async def test_mitre_mapping(self, copilot):
        """Test MITRE ATT&CK mapping functionality"""
        await copilot.initialize()

        techniques = await copilot._get_mitre_techniques("credential dumping")

        assert isinstance(techniques, list)
        assert len(techniques) > 0

        # Should contain relevant technique
        assert any("T1003" in technique for technique in techniques)

    @pytest.mark.asyncio
    async def test_context_enrichment(self, copilot):
        """Test context enrichment for queries"""
        await copilot.initialize()

        context = {
            "incident_id": "INC-2025-001",
            "severity": "high",
            "affected_systems": ["web-server-01", "db-server-02"],
            "attack_vectors": ["phishing", "lateral_movement"]
        }

        enriched = await copilot._enrich_context(context)

        assert "incident_details" in enriched
        assert enriched["severity_level"] == "high"
        assert len(enriched["system_count"]) == 2

    @pytest.mark.asyncio
    async def test_knowledge_base_search(self, copilot):
        """Test knowledge base search functionality"""
        await copilot.initialize()

        # Search for ransomware information
        results = await copilot._search_knowledge_base("ransomware prevention")

        assert isinstance(results, list)
        assert len(results) > 0

        # Results should be relevant
        for result in results:
            assert "content" in result
            assert "relevance_score" in result
            assert result["relevance_score"] > 0

    @pytest.mark.asyncio
    async def test_recommendation_generation(self, copilot):
        """Test security recommendation generation"""
        await copilot.initialize()

        context = {
            "threat_type": "apt",
            "attack_phase": "lateral_movement",
            "compromised_systems": 3
        }

        recommendations = await copilot._generate_recommendations(
            "How to contain APT lateral movement",
            context
        )

        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

        # Should be actionable recommendations
        for rec in recommendations:
            assert len(rec) > 10  # Not too short
            assert any(word in rec.lower() for word in ["isolate", "monitor", "block", "update"])

    @pytest.mark.asyncio
    async def test_process_event_integration(self, copilot, sample_event):
        """Test processing events for contextual analysis"""
        await copilot.initialize()

        result = await copilot.process_event(sample_event)

        # Copilot doesn't modify events, just analyzes
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == sample_event

        # But should update internal context
        assert copilot.events_analyzed > 0

    @pytest.mark.asyncio
    async def test_session_context_persistence(self, copilot):
        """Test session context persistence across queries"""
        await copilot.initialize()

        session_id = await copilot.create_session("analyst_456")

        # First query
        query1 = {
            "query": "I'm investigating a phishing attack",
            "session_id": session_id
        }
        response1 = await copilot.process_query(query1)

        # Second query in same session
        query2 = {
            "query": "What should I look for in email headers?",
            "session_id": session_id
        }
        response2 = await copilot.process_query(query2)

        # Second response should reference phishing context
        assert "phishing" in response2["response"]["text"].lower()

        await copilot.end_session(session_id)

    @pytest.mark.asyncio
    async def test_confidence_scoring(self, copilot):
        """Test confidence scoring in responses"""
        await copilot.initialize()

        # High confidence query (well-known topic)
        high_conf_query = {
            "query": "What is a SQL injection attack?",
            "query_type": "general_knowledge"
        }
        response1 = await copilot.process_query(high_conf_query)

        # Lower confidence query (very specific/obscure)
        low_conf_query = {
            "query": "Analyze this custom malware variant XYZ-2025-UNKNOWN",
            "query_type": "malware_analysis"
        }
        response2 = await copilot.process_query(low_conf_query)

        # First should have higher confidence
        assert response1["response"]["confidence"] >= response2["response"]["confidence"]

    @pytest.mark.asyncio
    async def test_follow_up_questions(self, copilot):
        """Test follow-up question generation"""
        await copilot.initialize()

        query = {
            "query": "We detected unusual network traffic",
            "query_type": "investigation"
        }

        response = await copilot.process_query(query)

        follow_ups = response["response"]["follow_up_questions"]
        assert len(follow_ups) > 0

        # Should ask relevant follow-up questions
        follow_up_text = " ".join(follow_ups).lower()
        assert any(keyword in follow_up_text for keyword in [
            "source", "destination", "volume", "time", "protocol"
        ])

    @pytest.mark.asyncio
    async def test_error_handling(self, copilot):
        """Test error handling with malformed queries"""
        await copilot.initialize()

        # Empty query
        empty_query = {"query": ""}
        response = await copilot.process_query(empty_query)
        assert "error" in response or response is None

        # Invalid session ID
        invalid_session_query = {
            "query": "Test query",
            "session_id": "non_existent_session"
        }
        response = await copilot.process_query(invalid_session_query)
        # Should handle gracefully

    @pytest.mark.asyncio
    async def test_cleanup(self, copilot):
        """Test agent cleanup"""
        await copilot.initialize()

        # Create some test data
        session_id = await copilot.create_session("test_analyst")
        await copilot.process_query({"query": "test", "session_id": session_id})

        assert len(copilot.active_sessions) > 0
        assert copilot.queries_processed > 0

        # Test cleanup
        await copilot.cleanup()
        assert len(copilot.active_sessions) == 0

    @pytest.mark.asyncio
    async def test_metrics(self, copilot):
        """Test metrics collection"""
        await copilot.initialize()

        # Process some queries
        await copilot.process_query({"query": "test query 1"})
        await copilot.process_query({"query": "test query 2"})

        metrics = copilot.get_metrics()

        assert "queries_processed" in metrics
        assert "active_sessions" in metrics
        assert "avg_response_time" in metrics
        assert "knowledge_base_size" in metrics

        assert metrics["queries_processed"] >= 2

    @pytest.mark.asyncio
    async def test_concurrent_queries(self, copilot):
        """Test handling concurrent queries"""
        await copilot.initialize()

        queries = [
            {"query": f"Test query {i}", "query_type": "general"}
            for i in range(5)
        ]

        # Process queries concurrently
        tasks = [copilot.process_query(query) for query in queries]
        responses = await asyncio.gather(*tasks)

        assert len(responses) == 5
        for response in responses:
            assert response is not None
            assert "response" in response

    @pytest.mark.asyncio
    async def test_query_templates(self, copilot):
        """Test predefined query templates"""
        await copilot.initialize()

        # Test different query types
        query_types = [
            "threat_analysis",
            "incident_response",
            "ioc_analysis",
            "malware_analysis",
            "forensics"
        ]

        for query_type in query_types:
            query = {
                "query": "Generic security question",
                "query_type": query_type
            }

            response = await copilot.process_query(query)
            assert response is not None

            # Response should be tailored to query type
            if query_type == "incident_response":
                assert any(word in response["response"]["text"].lower()
                          for word in ["contain", "eradicate", "recover"])


@pytest.mark.asyncio
async def test_realistic_analyst_workflow():
    """Test a realistic analyst workflow scenario"""
    copilot = AnalystCopilot()
    await copilot.initialize()

    # Analyst starts investigating a security incident
    session_id = await copilot.create_session("soc_analyst_1", {
        "response_format": "technical_details",
        "include_mitre_mapping": True
    })

    # Initial incident report
    initial_query = {
        "query": "We have multiple failed login attempts from external IPs. What should we investigate?",
        "query_type": "incident_response",
        "session_id": session_id,
        "context": {
            "severity": "medium",
            "affected_systems": ["web-app-01", "mail-server-01"]
        }
    }

    response1 = await copilot.process_query(initial_query)
    assert "brute force" in response1["response"]["text"].lower()

    # Follow-up question about specific IP
    followup_query = {
        "query": "The IP 192.168.100.50 appears most frequently. What should I check?",
        "query_type": "ioc_analysis",
        "session_id": session_id
    }

    response2 = await copilot.process_query(followup_query)
    assert "192.168.100.50" in response2["response"]["text"]

    # Ask for containment recommendations
    containment_query = {
        "query": "How should we contain this attack?",
        "query_type": "incident_response",
        "session_id": session_id
    }

    response3 = await copilot.process_query(containment_query)
    recommendations = response3["response"]["recommendations"]
    assert len(recommendations) > 0

    # Should provide actionable steps
    rec_text = " ".join(recommendations).lower()
    assert any(word in rec_text for word in ["block", "isolate", "monitor"])

    await copilot.end_session(session_id)
    await copilot.cleanup()


if __name__ == "__main__":
    pytest.main([__file__])