#!/usr/bin/env python3
"""
SATRIA AI Phase 3 Integration Test Script
Test autonomous response, multi-vendor orchestration, forensics, and QDE personas
"""

import asyncio
import logging
import json
import sys
import os
from datetime import datetime, timezone
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from satria.models.events import BaseEvent, EventCategory, EventClass, Confidence
from satria.core.quantum_decision_engine import (
    qde, DecisionContext, Persona
)
from satria.agents.autonomous.response_orchestrator import autonomous_response_orchestrator
from satria.agents.orchestration.multi_vendor_orchestrator import multi_vendor_orchestrator
from satria.agents.forensics.digital_forensics_analyzer import digital_forensics_analyzer

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Phase3IntegrationTester:
    """Test Phase 3 integration capabilities"""

    def __init__(self):
        self.test_results = {}
        self.test_events = []

    async def run_all_tests(self):
        """Run comprehensive Phase 3 integration tests"""
        logger.info("🚀 Starting SATRIA AI Phase 3 Integration Tests")

        # Initialize components
        await self._initialize_components()

        # Test scenarios
        test_scenarios = [
            ("QDE Advanced Personas", self._test_qde_personas),
            ("Autonomous Response Orchestrator", self._test_autonomous_response),
            ("Multi-Vendor Orchestration", self._test_multi_vendor),
            ("Digital Forensics Analysis", self._test_forensics),
            ("End-to-End Integration", self._test_e2e_integration),
        ]

        for test_name, test_func in test_scenarios:
            logger.info(f"🧪 Running test: {test_name}")
            try:
                result = await test_func()
                self.test_results[test_name] = {
                    "status": "PASS" if result else "FAIL",
                    "details": result
                }
                status_emoji = "✅" if result else "❌"
                logger.info(f"{status_emoji} {test_name}: {'PASSED' if result else 'FAILED'}")
            except Exception as e:
                self.test_results[test_name] = {
                    "status": "ERROR",
                    "error": str(e)
                }
                logger.error(f"❌ {test_name}: ERROR - {e}")

        # Generate report
        await self._generate_test_report()

    async def _initialize_components(self):
        """Initialize all Phase 3 components"""
        logger.info("📋 Initializing Phase 3 components...")

        try:
            # Initialize autonomous response orchestrator
            await autonomous_response_orchestrator.initialize()
            logger.info("✅ Autonomous Response Orchestrator initialized")

            # Initialize multi-vendor orchestrator
            await multi_vendor_orchestrator.initialize()
            logger.info("✅ Multi-Vendor Orchestrator initialized")

            # Initialize forensics analyzer
            await digital_forensics_analyzer.initialize()
            logger.info("✅ Digital Forensics Analyzer initialized")

            logger.info("🎯 All components initialized successfully")

        except Exception as e:
            logger.error(f"❌ Component initialization failed: {e}")
            raise

    async def _test_qde_personas(self) -> bool:
        """Test QDE advanced persona selection"""
        try:
            logger.info("🔮 Testing QDE Advanced Personas...")

            test_cases = [
                # High-risk malware detection
                {
                    "name": "High-Risk Malware",
                    "context": DecisionContext(
                        risk_score=0.9,
                        confidence=0.8,
                        business_impact="HIGH",
                        attack_stage="Initial Access",
                        affected_entities=["server-01", "workstation-05"]
                    ),
                    "expected_persona": Persona.MR_ROBOT
                },
                # APT Campaign
                {
                    "name": "APT Campaign",
                    "context": DecisionContext(
                        risk_score=0.7,
                        confidence=0.6,
                        business_impact="CRITICAL",
                        attack_stage="Lateral Movement",
                        affected_entities=["domain-controller", "file-server"]
                    ),
                    "expected_persona": Persona.PURPLE_TEAM
                },
                # Early reconnaissance
                {
                    "name": "Early Reconnaissance",
                    "context": DecisionContext(
                        risk_score=0.4,
                        confidence=0.9,
                        business_impact="LOW",
                        attack_stage="Reconnaissance",
                        affected_entities=["external-ip"],
                        time_pressure=0.2
                    ),
                    "expected_persona": Persona.THREAT_HUNTER
                },
                # Compliance incident
                {
                    "name": "Data Breach",
                    "context": DecisionContext(
                        risk_score=0.8,
                        confidence=0.7,
                        business_impact="CRITICAL",
                        attack_stage="Data Exfiltration",
                        affected_entities=["database-prod"]
                    ),
                    "expected_persona": [Persona.COMPLIANCE_OFFICER, Persona.INCIDENT_COMMANDER]
                }
            ]

            results = []
            for test_case in test_cases:
                decision = await qde.decide(test_case["context"])

                expected = test_case["expected_persona"]
                actual = decision.persona_mix.dominant_persona

                # Check if expected persona is in top 2
                if isinstance(expected, list):
                    success = actual in expected or decision.persona_mix.secondary_persona in expected
                else:
                    success = actual == expected

                results.append(success)

                logger.info(f"  📊 {test_case['name']}: "
                          f"Expected {expected}, Got {actual} "
                          f"(Secondary: {decision.persona_mix.secondary_persona}) "
                          f"{'✅' if success else '❌'}")

                logger.info(f"    🔍 Reasoning: {decision.reasoning}")

            # QDE metrics
            metrics = qde.get_metrics()
            logger.info(f"📈 QDE Metrics: {json.dumps(metrics, indent=2)}")

            return all(results)

        except Exception as e:
            logger.error(f"QDE test failed: {e}")
            return False

    async def _test_autonomous_response(self) -> bool:
        """Test autonomous response orchestrator"""
        try:
            logger.info("🤖 Testing Autonomous Response Orchestrator...")

            # Create test event
            malware_event = BaseEvent(
                event_type="malware_detection",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                source_agent="test_agent",
                confidence=Confidence.HIGH,
                risk_score=85,
                enrichment={
                    "entity_ids": {
                        "host": "workstation-01",
                        "file_hash": "abc123def456",
                        "user": "john.doe"
                    },
                    "message": "Advanced malware detected on workstation"
                }
            )

            # Process event
            result_events = await autonomous_response_orchestrator.process_event(malware_event)

            # Check results
            response_event = next((e for e in result_events if e.event_type == "autonomous_response_initiated"), None)
            success = response_event is not None

            if success:
                logger.info("✅ Autonomous response generated successfully")
                logger.info(f"  📋 Response plan: {response_event.enrichment.get('response_plan', {})}")
            else:
                logger.error("❌ No autonomous response generated")

            # Check metrics
            metrics = autonomous_response_orchestrator.get_metrics()
            logger.info(f"📊 Response Orchestrator Metrics: {json.dumps(metrics, indent=2)}")

            return success

        except Exception as e:
            logger.error(f"Autonomous response test failed: {e}")
            return False

    async def _test_multi_vendor(self) -> bool:
        """Test multi-vendor orchestration"""
        try:
            logger.info("🔗 Testing Multi-Vendor Orchestration...")

            # Create test event
            network_event = BaseEvent(
                event_type="network_anomaly",
                event_category=EventCategory.NETWORK_ACTIVITY,
                event_class=EventClass.NETWORK_CONNECTION_QUERY,
                timestamp=datetime.now(timezone.utc),
                source_agent="test_agent",
                confidence=Confidence.HIGH,
                risk_score=75,
                enrichment={
                    "entity_ids": {
                        "src_ip": "192.168.1.100",
                        "dst_ip": "malicious.com",
                        "protocol": "tcp"
                    },
                    "message": "Suspicious network communication detected"
                }
            )

            # Process event
            result_events = await multi_vendor_orchestrator.process_event(network_event)

            # Check results
            orchestration_event = next((e for e in result_events if e.event_type == "multi_vendor_orchestration"), None)
            success = orchestration_event is not None

            if success:
                logger.info("✅ Multi-vendor orchestration completed")
                orchestration_data = orchestration_event.enrichment.get('orchestration', {})
                logger.info(f"  🔧 Vendors involved: {orchestration_data.get('vendors_involved', [])}")
                logger.info(f"  📝 Actions executed: {orchestration_data.get('action_count', 0)}")
            else:
                logger.error("❌ No multi-vendor orchestration performed")

            # Check metrics
            metrics = multi_vendor_orchestrator.get_metrics()
            logger.info(f"📊 Multi-Vendor Metrics: {json.dumps(metrics, indent=2)}")

            return success

        except Exception as e:
            logger.error(f"Multi-vendor test failed: {e}")
            return False

    async def _test_forensics(self) -> bool:
        """Test digital forensics analysis"""
        try:
            logger.info("🔬 Testing Digital Forensics Analysis...")

            # Create test event
            forensic_event = BaseEvent(
                event_type="system_compromise",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                source_agent="test_agent",
                confidence=Confidence.HIGH,
                risk_score=88,
                enrichment={
                    "entity_ids": {
                        "host": "server-db01",
                        "file_path": "/suspicious/malware.exe",
                        "process_id": "1234",
                        "user": "admin"
                    },
                    "message": "System compromise detected - forensic analysis required"
                }
            )

            # Process event
            result_events = await digital_forensics_analyzer.process_event(forensic_event)

            # Check results
            forensic_result = next((e for e in result_events if e.event_type == "forensic_analysis_completed"), None)
            success = forensic_result is not None

            if success:
                logger.info("✅ Forensic analysis completed")
                forensic_data = forensic_result.enrichment.get('forensic_case', {})
                logger.info(f"  📁 Case ID: {forensic_data.get('case_id')}")
                logger.info(f"  🔍 Evidence collected: {forensic_data.get('evidence_count', 0)}")
                logger.info(f"  📋 Findings: {forensic_data.get('findings_count', 0)}")
            else:
                logger.error("❌ No forensic analysis performed")

            # Check metrics
            metrics = digital_forensics_analyzer.get_metrics()
            logger.info(f"📊 Forensics Metrics: {json.dumps(metrics, indent=2)}")

            return success

        except Exception as e:
            logger.error(f"Forensics test failed: {e}")
            return False

    async def _test_e2e_integration(self) -> bool:
        """Test end-to-end integration of all Phase 3 components"""
        try:
            logger.info("🌐 Testing End-to-End Integration...")

            # Create complex incident
            apt_event = BaseEvent(
                event_type="advanced_persistent_threat",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                source_agent="test_agent",
                confidence=Confidence.HIGH,
                risk_score=95,
                enrichment={
                    "entity_ids": {
                        "host": "domain-controller",
                        "src_ip": "attacker.evil.com",
                        "user": "compromised.admin",
                        "file_hash": "deadbeef123456",
                        "process_name": "svchost.exe"
                    },
                    "message": "Advanced Persistent Threat detected - multi-stage attack in progress"
                }
            )

            results = []

            # 1. QDE Decision
            context = DecisionContext(
                risk_score=0.95,
                confidence=0.88,
                business_impact="CRITICAL",
                attack_stage="Lateral Movement",
                affected_entities=["domain-controller", "file-server", "workstation-01"]
            )
            qde_decision = await qde.decide(context)
            results.append(qde_decision.persona_mix.dominant_persona is not None)
            logger.info(f"  🔮 QDE Decision: {qde_decision.persona_mix.dominant_persona.value}")

            # 2. Autonomous Response
            response_events = await autonomous_response_orchestrator.process_event(apt_event)
            response_generated = any(e.event_type == "autonomous_response_initiated" for e in response_events)
            results.append(response_generated)
            logger.info(f"  🤖 Autonomous Response: {'Generated' if response_generated else 'Failed'}")

            # 3. Multi-Vendor Orchestration
            vendor_events = await multi_vendor_orchestrator.process_event(apt_event)
            vendor_orchestrated = any(e.event_type == "multi_vendor_orchestration" for e in vendor_events)
            results.append(vendor_orchestrated)
            logger.info(f"  🔗 Multi-Vendor: {'Orchestrated' if vendor_orchestrated else 'Failed'}")

            # 4. Forensic Analysis
            forensic_events = await digital_forensics_analyzer.process_event(apt_event)
            forensic_completed = any(e.event_type == "forensic_analysis_completed" for e in forensic_events)
            results.append(forensic_completed)
            logger.info(f"  🔬 Forensics: {'Completed' if forensic_completed else 'Failed'}")

            # All components should work together
            success = all(results)
            logger.info(f"🎯 End-to-End Integration: {'SUCCESS' if success else 'FAILED'}")

            return success

        except Exception as e:
            logger.error(f"E2E integration test failed: {e}")
            return False

    async def _generate_test_report(self):
        """Generate comprehensive test report"""
        logger.info("📄 Generating Test Report...")

        passed = sum(1 for r in self.test_results.values() if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results.values() if r["status"] == "FAIL")
        errors = sum(1 for r in self.test_results.values() if r["status"] == "ERROR")
        total = len(self.test_results)

        report = {
            "test_summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "success_rate": f"{(passed/total)*100:.1f}%" if total > 0 else "0%"
            },
            "test_results": self.test_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "satria_version": "3.0.0",
            "phase": "Phase 3 - Orchestration"
        }

        # Save report
        with open("phase3_test_report.json", "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        print("\n" + "="*80)
        print("🎯 SATRIA AI Phase 3 Integration Test Results")
        print("="*80)
        print(f"📊 Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Errors: {errors}")
        print(f"📈 Success Rate: {report['test_summary']['success_rate']}")
        print("="*80)

        for test_name, result in self.test_results.items():
            status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}[result["status"]]
            print(f"{status_emoji} {test_name}: {result['status']}")

        print("\n📄 Full report saved to: phase3_test_report.json")

        if passed == total:
            print("🎉 All tests passed! SATRIA AI Phase 3 is ready for deployment!")
        else:
            print("🔧 Some tests failed. Please review the results and fix issues.")


async def main():
    """Main test execution"""
    tester = Phase3IntegrationTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())