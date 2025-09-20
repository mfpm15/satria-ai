"""
Tests for SATRIA AI Enterprise Compliance Module
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from satria.enterprise.compliance import (
    ComplianceEngine,
    ComplianceFramework,
    ComplianceRequirement,
    ComplianceControl,
    ComplianceStatus
)


class TestComplianceEngine:
    """Test compliance engine functionality"""

    @pytest.fixture
    def compliance_engine(self):
        """Create a test compliance engine instance"""
        return ComplianceEngine()

    def test_compliance_engine_initialization(self, compliance_engine):
        """Test compliance engine initializes correctly"""
        assert compliance_engine is not None
        assert hasattr(compliance_engine, 'frameworks')
        assert hasattr(compliance_engine, 'requirements')
        assert hasattr(compliance_engine, 'controls')

    def test_load_frameworks(self, compliance_engine):
        """Test loading compliance frameworks"""
        compliance_engine.load_frameworks()

        # Check that default frameworks are loaded
        assert ComplianceFramework.SOC2 in compliance_engine.frameworks
        assert ComplianceFramework.GDPR in compliance_engine.frameworks
        assert ComplianceFramework.ISO27001 in compliance_engine.frameworks

    def test_compliance_requirement_creation(self):
        """Test compliance requirement creation"""
        requirement = ComplianceRequirement(
            id="test-req-001",
            framework=ComplianceFramework.SOC2,
            category="security",
            title="Test Requirement",
            description="Test requirement description",
            control_objectives=["Test objective"]
        )

        assert requirement.id == "test-req-001"
        assert requirement.framework == ComplianceFramework.SOC2
        assert requirement.status == ComplianceStatus.NOT_ASSESSED

    def test_compliance_control_creation(self):
        """Test compliance control creation"""
        control = ComplianceControl(
            id="test-ctrl-001",
            requirement_id="test-req-001",
            name="Test Control",
            description="Test control description",
            control_type="preventive",
            frequency="daily"
        )

        assert control.id == "test-ctrl-001"
        assert control.requirement_id == "test-req-001"
        assert control.status == ComplianceStatus.NOT_ASSESSED

    @pytest.mark.asyncio
    async def test_assess_compliance(self, compliance_engine):
        """Test compliance assessment"""
        # Mock the assessment
        with patch.object(compliance_engine, '_assess_framework') as mock_assess:
            mock_assess.return_value = {
                'score': 85.0,
                'status': 'compliant',
                'findings': []
            }

            result = await compliance_engine.assess_compliance(ComplianceFramework.SOC2)

            assert result['score'] == 85.0
            assert result['status'] == 'compliant'
            mock_assess.assert_called_once_with(ComplianceFramework.SOC2)

    @pytest.mark.asyncio
    async def test_generate_report(self, compliance_engine):
        """Test compliance report generation"""
        report_data = {
            'framework': ComplianceFramework.SOC2,
            'period_start': datetime.now(),
            'period_end': datetime.now(),
            'report_type': 'assessment'
        }

        with patch.object(compliance_engine, '_generate_assessment_report') as mock_report:
            mock_report.return_value = {
                'report_id': 'test-report-001',
                'framework': 'SOC2',
                'overall_score': 85.0
            }

            result = await compliance_engine.generate_report(report_data)

            assert 'report_id' in result
            assert result['framework'] == 'SOC2'

    def test_get_status(self, compliance_engine):
        """Test getting compliance status"""
        status = compliance_engine.get_status()

        assert 'active_frameworks' in status
        assert 'total_requirements' in status
        assert 'assessment_status' in status
        assert isinstance(status['active_frameworks'], list)


class TestComplianceFrameworks:
    """Test compliance framework enums"""

    def test_compliance_framework_values(self):
        """Test that all expected frameworks are defined"""
        expected_frameworks = [
            'SOC2', 'ISO27001', 'GDPR', 'HIPAA', 'PCI_DSS', 'NIST_CSF'
        ]

        for framework in expected_frameworks:
            assert hasattr(ComplianceFramework, framework)

    def test_compliance_status_values(self):
        """Test that all expected status values are defined"""
        expected_statuses = [
            'NOT_ASSESSED', 'COMPLIANT', 'NON_COMPLIANT', 'PARTIALLY_COMPLIANT'
        ]

        for status in expected_statuses:
            assert hasattr(ComplianceStatus, status)


@pytest.mark.integration
class TestComplianceIntegration:
    """Integration tests for compliance module"""

    @pytest.mark.asyncio
    async def test_full_compliance_workflow(self):
        """Test complete compliance assessment workflow"""
        engine = ComplianceEngine()

        # Initialize frameworks
        engine.load_frameworks()

        # Mock database operations
        with patch.object(engine, 'initialize_database') as mock_db:
            mock_db.return_value = True

            # Test initialization
            result = engine.initialize_database()
            assert result is True

        # Test status check
        status = engine.get_status()
        assert isinstance(status, dict)
        assert 'active_frameworks' in status