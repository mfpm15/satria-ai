"""
SATRIA Red Team MCP Gateway
Safe integration with HexStrike AI and PentestGPT for controlled red team operations
"""

import asyncio
import logging
import json
import re
import subprocess
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlparse
import hashlib
import tempfile
import os

from satria.models.events import BaseEvent, EventCategory, EventClass, Severity, Confidence
from satria.core.config import settings
from satria.core.event_bus import publish_event


class ToolCategory(str, Enum):
    """HexStrike tool categories"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class SafetyLevel(str, Enum):
    """Tool safety levels"""
    SAFE = "safe"          # Read-only, no impact
    MODERATE = "moderate"  # Limited impact, reversible
    RISKY = "risky"       # Potential impact, needs approval
    DANGEROUS = "dangerous" # High impact, restricted


@dataclass
class ToolPolicy:
    """Policy for tool usage"""
    tool_name: str
    category: ToolCategory
    safety_level: SafetyLevel
    max_concurrency: int = 1
    max_duration_minutes: int = 10
    rate_limit_per_hour: int = 100
    requires_approval: bool = False
    allowed_targets: List[str] = field(default_factory=list)
    blocked_targets: List[str] = field(default_factory=list)
    allowed_args: List[str] = field(default_factory=list)
    blocked_args: List[str] = field(default_factory=list)


@dataclass
class ExecutionContext:
    """Context for tool execution"""
    session_id: str
    user_id: str
    target_scope: List[str]
    time_budget: timedelta
    approval_status: str = "pending"
    safety_check_passed: bool = False
    purpose: str = "purple_team_validation"


@dataclass
class ToolExecution:
    """Tool execution record"""
    execution_id: str
    tool_name: str
    command: str
    args: List[str]
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    artifacts: List[str] = field(default_factory=list)
    safety_violations: List[str] = field(default_factory=list)


class RedTeamGateway:
    """
    Gateway for safe HexStrike AI integration

    Provides controlled access to 150+ pentest tools with:
    - Scope allowlisting
    - Rate limiting
    - PII masking
    - Safety checks
    - Audit logging
    """

    def __init__(self):
        self.logger = logging.getLogger("satria.red_team_gateway")

        # Tool policies
        self.tool_policies = self._initialize_tool_policies()

        # Runtime state
        self.active_executions: Dict[str, ToolExecution] = {}
        self.execution_history: List[ToolExecution] = []

        # Safety configuration
        self.scope_allowlist = self._load_scope_allowlist()
        self.pii_patterns = self._load_pii_patterns()

        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}

    def _initialize_tool_policies(self) -> Dict[str, ToolPolicy]:
        """Initialize tool policies based on HexStrike tool catalog"""
        policies = {}

        # Safe reconnaissance tools
        safe_recon_tools = [
            "subfinder", "amass", "assetfinder", "findomain",
            "dnsx", "shuffledns", "massdns", "httpx", "naabu"
        ]

        for tool in safe_recon_tools:
            policies[tool] = ToolPolicy(
                tool_name=tool,
                category=ToolCategory.RECONNAISSANCE,
                safety_level=SafetyLevel.SAFE,
                max_concurrency=3,
                max_duration_minutes=15,
                rate_limit_per_hour=50,
                requires_approval=False
            )

        # Moderate scanning tools
        moderate_scan_tools = [
            "nuclei", "nmap", "masscan", "rustscan", "zmap"
        ]

        for tool in moderate_scan_tools:
            policies[tool] = ToolPolicy(
                tool_name=tool,
                category=ToolCategory.SCANNING,
                safety_level=SafetyLevel.MODERATE,
                max_concurrency=2,
                max_duration_minutes=30,
                rate_limit_per_hour=20,
                requires_approval=False,
                blocked_args=["-sS", "-sU", "--script=*exploit*", "--max-rate=1000"]
            )

        # Risky enumeration tools
        risky_enum_tools = [
            "feroxbuster", "gobuster", "ffuf", "dirsearch", "wfuzz"
        ]

        for tool in risky_enum_tools:
            policies[tool] = ToolPolicy(
                tool_name=tool,
                category=ToolCategory.ENUMERATION,
                safety_level=SafetyLevel.RISKY,
                max_concurrency=1,
                max_duration_minutes=20,
                rate_limit_per_hour=10,
                requires_approval=True,
                blocked_args=["--threads=100", "-t 100", "--rate=1000"]
            )

        # Dangerous exploitation tools (highly restricted)
        dangerous_tools = [
            "metasploit", "sqlmap", "burpsuite", "ghauri", "commix"
        ]

        for tool in dangerous_tools:
            policies[tool] = ToolPolicy(
                tool_name=tool,
                category=ToolCategory.EXPLOITATION,
                safety_level=SafetyLevel.DANGEROUS,
                max_concurrency=1,
                max_duration_minutes=10,
                rate_limit_per_hour=5,
                requires_approval=True,
                allowed_targets=["lab.satria.local", "192.168.56.0/24"],
                blocked_args=["--risk=3", "--level=5", "--batch"]
            )

        return policies

    def _load_scope_allowlist(self) -> Dict[str, List[str]]:
        """Load target scope allowlist"""
        return {
            "cidr_ranges": [
                "10.10.0.0/16",      # Lab network
                "192.168.56.0/24",   # Sandbox network
                "172.16.100.0/24"    # Purple team range
            ],
            "domains": [
                "lab.satria.local",
                "test.satria.local",
                "sandbox.satria.local"
            ],
            "ips": [
                "10.10.1.100",       # Web app target
                "10.10.1.101",       # Database target
                "192.168.56.10"      # VM target
            ]
        }

    def _load_pii_patterns(self) -> Dict[str, str]:
        """Load PII detection patterns"""
        return {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            "api_key": r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)[\s]*[:=][\s]*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            "password": r'(?i)(password|pwd|pass)[\s]*[:=][\s]*["\']?([A-Za-z0-9@#$%^&*!]{8,})["\']?'
        }

    async def execute_tool(self, tool_name: str, args: List[str],
                          context: ExecutionContext) -> ToolExecution:
        """
        Execute HexStrike tool with safety checks
        """
        execution_id = f"exec-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hash(tool_name + str(args)) % 10000:04d}"

        execution = ToolExecution(
            execution_id=execution_id,
            tool_name=tool_name,
            command=f"{tool_name} {' '.join(args)}",
            args=args,
            start_time=datetime.utcnow()
        )

        try:
            # Pre-execution safety checks
            safety_check = await self._perform_safety_checks(tool_name, args, context)
            if not safety_check["passed"]:
                execution.safety_violations = safety_check["violations"]
                execution.stderr = f"Safety check failed: {'; '.join(safety_check['violations'])}"
                execution.exit_code = -1
                return execution

            # Check rate limits
            if not self._check_rate_limits(tool_name):
                execution.stderr = "Rate limit exceeded"
                execution.exit_code = -2
                return execution

            # Execute tool via HexStrike MCP
            self.active_executions[execution_id] = execution
            result = await self._execute_via_hexstrike(tool_name, args, context)

            # Update execution record
            execution.end_time = datetime.utcnow()
            execution.exit_code = result.get("exit_code", 0)
            execution.stdout = await self._sanitize_output(result.get("stdout", ""))
            execution.stderr = await self._sanitize_output(result.get("stderr", ""))
            execution.artifacts = result.get("artifacts", [])

            # Generate event for Event Bus
            await self._generate_red_team_event(execution, context)

            self.logger.info(f"Tool execution completed: {execution_id}")

        except Exception as e:
            execution.end_time = datetime.utcnow()
            execution.exit_code = -999
            execution.stderr = f"Execution error: {str(e)}"
            self.logger.error(f"Tool execution failed {execution_id}: {e}")

        finally:
            # Cleanup
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]

            self.execution_history.append(execution)

            # Keep only last 1000 executions
            if len(self.execution_history) > 1000:
                self.execution_history = self.execution_history[-1000:]

        return execution

    async def _perform_safety_checks(self, tool_name: str, args: List[str],
                                   context: ExecutionContext) -> Dict[str, Any]:
        """Perform comprehensive safety checks"""
        violations = []

        # Check if tool is allowed
        if tool_name not in self.tool_policies:
            violations.append(f"Tool '{tool_name}' not in allowlist")

        policy = self.tool_policies.get(tool_name)
        if not policy:
            violations.append(f"No policy defined for tool '{tool_name}'")
            return {"passed": False, "violations": violations}

        # Check approval requirement
        if policy.requires_approval and context.approval_status != "approved":
            violations.append(f"Tool '{tool_name}' requires approval")

        # Check concurrency limits
        active_count = sum(1 for exec in self.active_executions.values()
                          if exec.tool_name == tool_name)
        if active_count >= policy.max_concurrency:
            violations.append(f"Concurrency limit exceeded for '{tool_name}' ({active_count}/{policy.max_concurrency})")

        # Check argument safety
        for arg in args:
            if any(blocked in arg.lower() for blocked in policy.blocked_args):
                violations.append(f"Blocked argument detected: {arg}")

        # Check target scope
        target_violations = await self._check_target_scope(args, context.target_scope)
        violations.extend(target_violations)

        # Check time budget
        if context.time_budget < timedelta(minutes=1):
            violations.append("Insufficient time budget")

        return {
            "passed": len(violations) == 0,
            "violations": violations,
            "policy": policy.tool_name if policy else None
        }

    async def _check_target_scope(self, args: List[str], allowed_scope: List[str]) -> List[str]:
        """Check if targets are within allowed scope"""
        violations = []

        # Extract potential targets from arguments
        targets = self._extract_targets_from_args(args)

        for target in targets:
            if not self._is_target_allowed(target, allowed_scope):
                violations.append(f"Target '{target}' not in allowed scope")

        return violations

    def _extract_targets_from_args(self, args: List[str]) -> List[str]:
        """Extract target IPs/domains from command arguments"""
        targets = []

        for arg in args:
            # Check for IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            targets.extend(re.findall(ip_pattern, arg))

            # Check for domain names
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            targets.extend(re.findall(domain_pattern, arg))

            # Check for CIDR ranges
            cidr_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b'
            targets.extend(re.findall(cidr_pattern, arg))

        return list(set(targets))  # Remove duplicates

    def _is_target_allowed(self, target: str, allowed_scope: List[str]) -> bool:
        """Check if target is within allowed scope"""
        # Check against allowlist
        for allowed in self.scope_allowlist["ips"]:
            if target == allowed:
                return True

        for allowed in self.scope_allowlist["domains"]:
            if target.endswith(allowed):
                return True

        # Check CIDR ranges
        try:
            target_ip = ipaddress.ip_address(target)
            for allowed_cidr in self.scope_allowlist["cidr_ranges"]:
                if target_ip in ipaddress.ip_network(allowed_cidr):
                    return True
        except ValueError:
            pass  # Not an IP address

        return False

    def _check_rate_limits(self, tool_name: str) -> bool:
        """Check rate limits for tool"""
        policy = self.tool_policies.get(tool_name)
        if not policy:
            return False

        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)

        # Initialize if not exists
        if tool_name not in self.rate_limits:
            self.rate_limits[tool_name] = []

        # Clean old entries
        self.rate_limits[tool_name] = [
            timestamp for timestamp in self.rate_limits[tool_name]
            if timestamp > hour_ago
        ]

        # Check limit
        if len(self.rate_limits[tool_name]) >= policy.rate_limit_per_hour:
            return False

        # Add current execution
        self.rate_limits[tool_name].append(now)
        return True

    async def _execute_via_hexstrike(self, tool_name: str, args: List[str],
                                   context: ExecutionContext) -> Dict[str, Any]:
        """Execute tool via HexStrike MCP server"""
        try:
            # Prepare execution environment
            timeout = self.tool_policies[tool_name].max_duration_minutes * 60

            # For now, simulate HexStrike execution
            # In production, this would call the actual HexStrike MCP server
            result = await self._simulate_tool_execution(tool_name, args, timeout)

            return result

        except Exception as e:
            self.logger.error(f"HexStrike execution error: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "artifacts": []
            }

    async def _simulate_tool_execution(self, tool_name: str, args: List[str],
                                     timeout: int) -> Dict[str, Any]:
        """Simulate tool execution for development/testing"""
        # Simulate different tool behaviors
        if tool_name == "nmap":
            stdout = """
            Starting Nmap 7.91 ( https://nmap.org )
            Nmap scan report for target.lab.satria.local (10.10.1.100)
            Host is up (0.001s latency).
            PORT     STATE SERVICE
            22/tcp   open  ssh
            80/tcp   open  http
            443/tcp  open  https
            """

        elif tool_name == "nuclei":
            stdout = """
            [INF] Using Nuclei Engine 2.9.15
            [INF] Loaded 3847 templates
            [MEDIUM] SSL Certificate Transparency - target.lab.satria.local
            [LOW] HTTP Server Header - target.lab.satria.local
            """

        elif tool_name == "subfinder":
            stdout = """
            api.target.lab.satria.local
            www.target.lab.satria.local
            mail.target.lab.satria.local
            test.target.lab.satria.local
            """

        else:
            stdout = f"Simulated output for {tool_name} with args: {' '.join(args)}"

        # Simulate execution delay
        await asyncio.sleep(min(2, timeout/10))

        return {
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
            "artifacts": [f"/tmp/{tool_name}_output_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"]
        }

    async def _sanitize_output(self, output: str) -> str:
        """Sanitize output by masking PII"""
        sanitized = output

        for pii_type, pattern in self.pii_patterns.items():
            sanitized = re.sub(pattern, f"[MASKED_{pii_type.upper()}]", sanitized)

        return sanitized

    async def _generate_red_team_event(self, execution: ToolExecution,
                                     context: ExecutionContext) -> None:
        """Generate event for SATRIA Event Bus"""
        event = BaseEvent(
            event_type="red_team_tool_execution",
            event_category=EventCategory.DISCOVERY,
            event_class=EventClass.DEVICE_INVENTORY,
            source_agent="red_team_gateway",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            entities=[],
            evidence=[
                {
                    "source": "red_team_execution",
                    "value": execution.command,
                    "context": {
                        "tool_name": execution.tool_name,
                        "exit_code": execution.exit_code,
                        "duration_seconds": (execution.end_time - execution.start_time).total_seconds() if execution.end_time else 0,
                        "session_id": context.session_id,
                        "purpose": context.purpose
                    }
                }
            ],
            enrichment={
                "execution_id": execution.execution_id,
                "tool_category": self.tool_policies.get(execution.tool_name, {}).category if execution.tool_name in self.tool_policies else "unknown",
                "safety_level": self.tool_policies.get(execution.tool_name, {}).safety_level if execution.tool_name in self.tool_policies else "unknown",
                "artifacts": execution.artifacts,
                "safety_violations": execution.safety_violations
            },
            destinations=["red_team_processor", "operational_memory", "threat_intel_enricher"]
        )

        # Publish to Event Bus
        await publish_event(event)

    async def create_purple_team_session(self, scenario: str, targets: List[str],
                                       duration_hours: int = 2) -> str:
        """Create controlled purple team session"""
        session_id = f"purple-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        context = ExecutionContext(
            session_id=session_id,
            user_id="purple_team_operator",
            target_scope=targets,
            time_budget=timedelta(hours=duration_hours),
            approval_status="approved",  # Pre-approved for purple team
            purpose=f"purple_team_validation_{scenario}"
        )

        self.logger.info(f"Created purple team session {session_id} for scenario '{scenario}'")
        return session_id

    def get_execution_history(self, session_id: Optional[str] = None,
                            limit: int = 100) -> List[Dict[str, Any]]:
        """Get execution history"""
        history = self.execution_history

        if session_id:
            history = [exec for exec in history if exec.execution_id.startswith(session_id)]

        return [
            {
                "execution_id": exec.execution_id,
                "tool_name": exec.tool_name,
                "command": exec.command,
                "start_time": exec.start_time.isoformat(),
                "end_time": exec.end_time.isoformat() if exec.end_time else None,
                "exit_code": exec.exit_code,
                "duration_seconds": (exec.end_time - exec.start_time).total_seconds() if exec.end_time else 0,
                "safety_violations": exec.safety_violations
            }
            for exec in history[-limit:]
        ]

    def get_metrics(self) -> Dict[str, Any]:
        """Get gateway metrics"""
        recent_executions = [exec for exec in self.execution_history
                           if exec.start_time > datetime.utcnow() - timedelta(hours=24)]

        tool_usage = {}
        for exec in recent_executions:
            tool_usage[exec.tool_name] = tool_usage.get(exec.tool_name, 0) + 1

        success_rate = sum(1 for exec in recent_executions if exec.exit_code == 0) / len(recent_executions) if recent_executions else 0

        return {
            "total_executions": len(self.execution_history),
            "recent_executions_24h": len(recent_executions),
            "active_executions": len(self.active_executions),
            "tool_usage_24h": tool_usage,
            "success_rate_24h": success_rate,
            "configured_tools": len(self.tool_policies),
            "rate_limits_active": len(self.rate_limits)
        }


# Global gateway instance
red_team_gateway = RedTeamGateway()