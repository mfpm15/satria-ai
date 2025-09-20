"""
SATRIA AI Interactive Chat Interface
User-friendly chat interface for cybersecurity operations
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json
import uuid

from satria.core.llm_client import llm_client, LLMMessage
from satria.agents.intelligence import ThreatIntelligenceAgent, BehavioralAnomalyDetector
from satria.agents.copilot.analyst_copilot import AnalystCopilot
from satria.integrations.red_team_gateway import red_team_gateway

logger = logging.getLogger(__name__)

class TaskType(Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    THREAT_ANALYSIS = "threat_analysis"
    INCIDENT_RESPONSE = "incident_response"
    NETWORK_ANALYSIS = "network_analysis"
    GENERAL_QUERY = "general_query"

class TeamRole(Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    AUTO = "auto"

@dataclass
class ChatMessage:
    id: str
    timestamp: datetime
    user_input: str
    ai_response: str
    task_type: TaskType
    team_role: TeamRole
    execution_details: Dict[str, Any]
    artifacts: List[Dict[str, Any]]

@dataclass
class UserRequest:
    id: str
    timestamp: datetime
    user_input: str
    parsed_intent: Dict[str, Any]
    recommended_team: TeamRole
    task_type: TaskType
    confidence: float

class SATRIAChatInterface:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.chat_history: List[ChatMessage] = []
        self.threat_agent = ThreatIntelligenceAgent()
        self.anomaly_detector = BehavioralAnomalyDetector()
        self.analyst_copilot = AnalystCopilot()

    async def process_user_request(self, user_input: str) -> ChatMessage:
        """Process user request and execute appropriate cybersecurity tasks"""

        # Parse user intent
        request = await self._parse_user_intent(user_input)

        # Execute based on team role and task type
        if request.recommended_team == TeamRole.RED_TEAM:
            response = await self._execute_red_team_task(request)
        elif request.recommended_team == TeamRole.BLUE_TEAM:
            response = await self._execute_blue_team_task(request)
        elif request.recommended_team == TeamRole.PURPLE_TEAM:
            response = await self._execute_purple_team_task(request)
        else:
            response = await self._execute_general_task(request)

        # Create chat message
        chat_message = ChatMessage(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            user_input=user_input,
            ai_response=response["response"],
            task_type=request.task_type,
            team_role=request.recommended_team,
            execution_details=response.get("details", {}),
            artifacts=response.get("artifacts", [])
        )

        self.chat_history.append(chat_message)
        return chat_message

    async def _parse_user_intent(self, user_input: str) -> UserRequest:
        """Parse user input to understand intent and determine appropriate team"""

        system_prompt = """
        Anda adalah SATRIA AI, sistem cybersecurity yang cerdas. Analisis permintaan user dan tentukan:
        1. Jenis tugas (reconnaissance, vulnerability_assessment, threat_analysis, incident_response, network_analysis, general_query)
        2. Tim yang tepat (red_team untuk offensive security, blue_team untuk defensive, purple_team untuk gabungan)
        3. Intent parsing untuk mengekstrak target, metode, dan parameter

        Contoh:
        - "cek IP di google.com" -> red_team, reconnaissance
        - "analisis log serangan" -> blue_team, threat_analysis
        - "scan vulnerability website" -> red_team, vulnerability_assessment
        - "monitor anomali network" -> blue_team, network_analysis

        Berikan response dalam format JSON:
        {
            "task_type": "reconnaissance",
            "team_role": "red_team",
            "confidence": 0.9,
            "parsed_intent": {
                "target": "google.com",
                "action": "ip_discovery",
                "method": "dns_lookup",
                "parameters": {}
            }
        }
        """

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=f"User request: {user_input}")
        ]

        try:
            response = await llm_client.chat_completion(messages)

            # Parse JSON response
            parsed = json.loads(response.content)

            return UserRequest(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                user_input=user_input,
                parsed_intent=parsed.get("parsed_intent", {}),
                recommended_team=TeamRole(parsed.get("team_role", "auto")),
                task_type=TaskType(parsed.get("task_type", "general_query")),
                confidence=parsed.get("confidence", 0.5)
            )

        except Exception as e:
            logger.error(f"Failed to parse user intent: {e}")

            # Fallback to simple parsing
            return UserRequest(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                user_input=user_input,
                parsed_intent={"target": "unknown", "action": "general"},
                recommended_team=TeamRole.AUTO,
                task_type=TaskType.GENERAL_QUERY,
                confidence=0.3
            )

    async def _execute_red_team_task(self, request: UserRequest) -> Dict[str, Any]:
        """Execute red team (offensive security) tasks"""

        intent = request.parsed_intent
        target = intent.get("target", "")
        action = intent.get("action", "")

        response_text = ""
        artifacts = []
        details = {}

        try:
            if request.task_type == TaskType.RECONNAISSANCE:
                # DNS reconnaissance
                if "ip" in action.lower() or "dns" in action.lower():
                    result = await self._perform_dns_reconnaissance(target)
                    response_text = f"🔍 **Red Team Reconnaissance - {target}**\n\n"
                    response_text += f"**DNS Information:**\n"

                    for record_type, records in result.items():
                        response_text += f"- **{record_type}**: {', '.join(records)}\n"

                    artifacts.append({
                        "type": "dns_records",
                        "target": target,
                        "data": result
                    })

                # Port scanning
                elif "port" in action.lower() or "scan" in action.lower():
                    result = await self._perform_port_scan(target)
                    response_text = f"🎯 **Red Team Port Scanning - {target}**\n\n"
                    response_text += f"**Open Ports Found:**\n"

                    for port_info in result:
                        response_text += f"- **Port {port_info['port']}** ({port_info['protocol']}): {port_info['service']}\n"

                    artifacts.append({
                        "type": "port_scan",
                        "target": target,
                        "data": result
                    })

            elif request.task_type == TaskType.VULNERABILITY_ASSESSMENT:
                result = await self._perform_vulnerability_scan(target)
                response_text = f"🚨 **Red Team Vulnerability Assessment - {target}**\n\n"

                for vuln in result:
                    severity_emoji = "🔥" if vuln["severity"] == "high" else "⚠️" if vuln["severity"] == "medium" else "ℹ️"
                    response_text += f"{severity_emoji} **{vuln['title']}** ({vuln['severity']})\n"
                    response_text += f"   - {vuln['description']}\n\n"

                artifacts.append({
                    "type": "vulnerability_scan",
                    "target": target,
                    "data": result
                })

            details = {
                "team": "red_team",
                "task_type": request.task_type.value,
                "target": target,
                "execution_time": datetime.now().isoformat()
            }

        except Exception as e:
            response_text = f"❌ **Red Team Operation Failed**\n\nError: {str(e)}"
            logger.error(f"Red team task execution failed: {e}")

        return {
            "response": response_text,
            "artifacts": artifacts,
            "details": details
        }

    async def _execute_blue_team_task(self, request: UserRequest) -> Dict[str, Any]:
        """Execute blue team (defensive security) tasks"""

        intent = request.parsed_intent
        target = intent.get("target", "")

        response_text = ""
        artifacts = []
        details = {}

        try:
            if request.task_type == TaskType.THREAT_ANALYSIS:
                # Analyze threat indicators
                result = await self.threat_agent.analyze_threat({
                    "type": "domain" if "." in target else "general",
                    "value": target,
                    "source": "user_request"
                })

                response_text = f"🛡️ **Blue Team Threat Analysis - {target}**\n\n"
                response_text += f"**Threat Assessment:**\n"
                response_text += f"- **Risk Level**: {result.risk_level}\n"
                response_text += f"- **Confidence**: {result.confidence:.2%}\n"
                response_text += f"- **Threat Type**: {result.threat_type}\n\n"

                if result.indicators:
                    response_text += f"**Indicators of Compromise (IoCs):**\n"
                    for ioc in result.indicators[:5]:  # Show top 5
                        response_text += f"- {ioc['type']}: {ioc['value']} (confidence: {ioc['confidence']:.2%})\n"

                artifacts.append({
                    "type": "threat_analysis",
                    "target": target,
                    "data": {
                        "risk_level": result.risk_level,
                        "confidence": result.confidence,
                        "threat_type": result.threat_type,
                        "indicators": result.indicators
                    }
                })

            elif request.task_type == TaskType.NETWORK_ANALYSIS:
                # Monitor network for anomalies
                result = await self._perform_network_monitoring(target)
                response_text = f"🔒 **Blue Team Network Analysis - {target}**\n\n"

                response_text += f"**Network Status:**\n"
                response_text += f"- **Connection Status**: {result.get('status', 'unknown')}\n"
                response_text += f"- **Anomalies Detected**: {len(result.get('anomalies', []))}\n\n"

                if result.get('anomalies'):
                    response_text += f"**Anomalies Found:**\n"
                    for anomaly in result['anomalies'][:3]:  # Show top 3
                        response_text += f"- {anomaly['description']} (severity: {anomaly['severity']})\n"

                artifacts.append({
                    "type": "network_analysis",
                    "target": target,
                    "data": result
                })

            elif request.task_type == TaskType.INCIDENT_RESPONSE:
                # Incident response analysis
                result = await self._perform_incident_analysis(target)
                response_text = f"🚨 **Blue Team Incident Response - {target}**\n\n"

                response_text += f"**Incident Assessment:**\n"
                response_text += f"- **Severity**: {result.get('severity', 'unknown')}\n"
                response_text += f"- **Affected Systems**: {result.get('affected_systems', 0)}\n"
                response_text += f"- **Recommended Actions**: {len(result.get('recommendations', []))}\n\n"

                if result.get('recommendations'):
                    response_text += f"**Immediate Actions:**\n"
                    for rec in result['recommendations'][:3]:
                        response_text += f"- {rec}\n"

                artifacts.append({
                    "type": "incident_response",
                    "target": target,
                    "data": result
                })

            details = {
                "team": "blue_team",
                "task_type": request.task_type.value,
                "target": target,
                "execution_time": datetime.now().isoformat()
            }

        except Exception as e:
            response_text = f"❌ **Blue Team Operation Failed**\n\nError: {str(e)}"
            logger.error(f"Blue team task execution failed: {e}")

        return {
            "response": response_text,
            "artifacts": artifacts,
            "details": details
        }

    async def _execute_purple_team_task(self, request: UserRequest) -> Dict[str, Any]:
        """Execute purple team (collaborative) tasks"""

        response_text = f"🟣 **Purple Team Collaborative Analysis**\n\n"
        response_text += f"Executing both offensive and defensive analysis...\n\n"

        # Execute both red and blue team analysis
        red_result = await self._execute_red_team_task(request)
        blue_result = await self._execute_blue_team_task(request)

        response_text += f"**🔴 Red Team Results:**\n{red_result['response']}\n\n"
        response_text += f"**🔵 Blue Team Results:**\n{blue_result['response']}\n\n"

        response_text += f"**🟣 Purple Team Synthesis:**\n"
        response_text += f"- **Attack Surface**: Analyzed from red team perspective\n"
        response_text += f"- **Defense Posture**: Evaluated from blue team perspective\n"
        response_text += f"- **Recommendations**: Combined offensive and defensive insights\n"

        artifacts = red_result.get('artifacts', []) + blue_result.get('artifacts', [])

        details = {
            "team": "purple_team",
            "task_type": request.task_type.value,
            "execution_time": datetime.now().isoformat(),
            "red_team_details": red_result.get('details', {}),
            "blue_team_details": blue_result.get('details', {})
        }

        return {
            "response": response_text,
            "artifacts": artifacts,
            "details": details
        }

    async def _execute_general_task(self, request: UserRequest) -> Dict[str, Any]:
        """Execute general cybersecurity tasks"""

        response_text = f"🤖 **SATRIA AI General Analysis**\n\n"

        try:
            # Use analyst copilot for general queries
            analysis = await self.analyst_copilot.analyze_query(request.user_input)

            response_text += f"**Analysis Results:**\n"
            response_text += f"{analysis.get('summary', 'No analysis available')}\n\n"

            if analysis.get('recommendations'):
                response_text += f"**Recommendations:**\n"
                for rec in analysis['recommendations']:
                    response_text += f"- {rec}\n"

            artifacts = [{
                "type": "general_analysis",
                "query": request.user_input,
                "data": analysis
            }]

        except Exception as e:
            response_text += f"Unable to process general query: {str(e)}"
            artifacts = []

        details = {
            "team": "general",
            "task_type": request.task_type.value,
            "execution_time": datetime.now().isoformat()
        }

        return {
            "response": response_text,
            "artifacts": artifacts,
            "details": details
        }

    # Helper methods for specific operations
    async def _perform_dns_reconnaissance(self, target: str) -> Dict[str, List[str]]:
        """Perform DNS reconnaissance"""
        import socket
        import subprocess

        result = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}

        try:
            # A record (IPv4)
            ipv4 = socket.gethostbyname(target)
            result["A"].append(ipv4)

            # Try to get additional info via nslookup if available
            try:
                nslookup_result = subprocess.run(
                    ["nslookup", target],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Parse nslookup output for additional records
                lines = nslookup_result.stdout.split('\n')
                for line in lines:
                    if 'Address:' in line and '#' not in line:
                        ip = line.split(':')[-1].strip()
                        if ip not in result["A"]:
                            result["A"].append(ip)
            except:
                pass

        except Exception as e:
            result["A"].append(f"Resolution failed: {str(e)}")

        return result

    async def _perform_port_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform basic port scan"""
        import socket

        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]
        results = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    service = socket.getservbyport(port) if port < 1024 else "unknown"
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "status": "open"
                    })
            except:
                continue

        return results

    async def _perform_vulnerability_scan(self, target: str) -> List[Dict[str, Any]]:
        """Simulate vulnerability scanning"""
        # This is a simulation - in real implementation would use actual vuln scanners
        vulns = [
            {
                "title": "Open HTTP Service",
                "severity": "medium",
                "description": f"HTTP service detected on {target}. Consider using HTTPS.",
                "cve": "N/A"
            },
            {
                "title": "Information Disclosure",
                "severity": "low",
                "description": "Server headers may reveal version information.",
                "cve": "N/A"
            }
        ]

        return vulns

    async def _perform_network_monitoring(self, target: str) -> Dict[str, Any]:
        """Simulate network monitoring"""
        return {
            "status": "monitored",
            "anomalies": [
                {
                    "description": f"Unusual traffic pattern to {target}",
                    "severity": "low",
                    "timestamp": datetime.now().isoformat()
                }
            ],
            "baseline_established": True
        }

    async def _perform_incident_analysis(self, target: str) -> Dict[str, Any]:
        """Simulate incident analysis"""
        return {
            "severity": "medium",
            "affected_systems": 1,
            "recommendations": [
                "Monitor target for suspicious activity",
                "Review access logs",
                "Implement additional monitoring"
            ],
            "timeline": [
                {
                    "time": datetime.now().isoformat(),
                    "event": f"Analysis requested for {target}"
                }
            ]
        }

    def get_chat_history(self) -> List[Dict[str, Any]]:
        """Get formatted chat history"""
        return [
            {
                "id": msg.id,
                "timestamp": msg.timestamp.isoformat(),
                "user_input": msg.user_input,
                "ai_response": msg.ai_response,
                "task_type": msg.task_type.value,
                "team_role": msg.team_role.value,
                "artifacts_count": len(msg.artifacts)
            }
            for msg in self.chat_history
        ]

# Global instance
chat_interface = SATRIAChatInterface()