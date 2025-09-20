"""
SATRIA AI Enterprise Governance & Access Management
Role-based access control, policy management, and enterprise security governance
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
import hashlib
import jwt
from pathlib import Path

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.config import settings


class UserRole(str, Enum):
    """Predefined user roles"""
    SUPER_ADMIN = "super_admin"
    SECURITY_ADMIN = "security_admin"
    SOC_MANAGER = "soc_manager"
    SECURITY_ANALYST = "security_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    THREAT_HUNTER = "threat_hunter"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    FORENSICS_ANALYST = "forensics_analyst"
    SECURITY_ARCHITECT = "security_architect"
    CISO = "ciso"
    READ_ONLY_USER = "read_only_user"


class Permission(str, Enum):
    """System permissions"""
    # Dashboard & Reporting
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_EXECUTIVE_REPORTS = "view_executive_reports"
    EXPORT_REPORTS = "export_reports"

    # Incident Management
    VIEW_INCIDENTS = "view_incidents"
    CREATE_INCIDENTS = "create_incidents"
    UPDATE_INCIDENTS = "update_incidents"
    CLOSE_INCIDENTS = "close_incidents"
    DELETE_INCIDENTS = "delete_incidents"

    # Investigation & Analysis
    CREATE_INVESTIGATIONS = "create_investigations"
    VIEW_INVESTIGATIONS = "view_investigations"
    UPDATE_INVESTIGATIONS = "update_investigations"
    ACCESS_FORENSICS = "access_forensics"

    # Response & Orchestration
    EXECUTE_RESPONSE_PLANS = "execute_response_plans"
    APPROVE_RESPONSES = "approve_responses"
    COORDINATE_RESPONSE = "coordinate_response"
    MANAGE_CONTAINMENT = "manage_containment"

    # Threat Intelligence
    VIEW_THREAT_INTEL = "view_threat_intel"
    UPDATE_THREAT_INTEL = "update_threat_intel"
    MANAGE_INDICATORS = "manage_indicators"

    # System Configuration
    CONFIGURE_AGENTS = "configure_agents"
    MANAGE_INTEGRATIONS = "manage_integrations"
    UPDATE_POLICIES = "update_policies"
    MANAGE_RULES = "manage_rules"

    # User Management
    VIEW_USERS = "view_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    MANAGE_ROLES = "manage_roles"

    # Audit & Compliance
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_AUDIT_LOGS = "export_audit_logs"
    MANAGE_COMPLIANCE = "manage_compliance"
    CONDUCT_ASSESSMENTS = "conduct_assessments"

    # System Administration
    SYSTEM_ADMINISTRATION = "system_administration"
    BACKUP_RESTORE = "backup_restore"
    MANAGE_LICENSES = "manage_licenses"


class ResourceType(str, Enum):
    """Protected resource types"""
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    THREAT_INTEL = "threat_intel"
    USER_ACCOUNT = "user_account"
    SYSTEM_CONFIG = "system_config"
    AUDIT_LOG = "audit_log"
    REPORT = "report"
    DASHBOARD = "dashboard"
    POLICY = "policy"
    EVIDENCE = "evidence"


class AccessLevel(str, Enum):
    """Access levels for resources"""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    OWNER = "owner"


@dataclass
class User:
    """User account information"""
    user_id: str
    username: str
    email: str
    full_name: str
    roles: List[UserRole] = field(default_factory=list)
    permissions: Set[Permission] = field(default_factory=set)
    department: str = ""
    manager: Optional[str] = None
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    password_last_changed: Optional[datetime] = None
    mfa_enabled: bool = False
    session_timeout: int = 3600  # seconds
    failed_login_attempts: int = 0
    account_locked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Role:
    """Role definition with permissions"""
    role_id: str
    name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    resource_access: Dict[ResourceType, AccessLevel] = field(default_factory=dict)
    inherits_from: List[str] = field(default_factory=list)
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """Security policy definition"""
    policy_id: str
    name: str
    description: str
    policy_type: str  # access, security, compliance, operational
    rules: List[Dict[str, Any]] = field(default_factory=list)
    applies_to: List[UserRole] = field(default_factory=list)
    enforcement_level: str = "enforced"  # enforced, advisory, disabled
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0"


@dataclass
class AuditLog:
    """Audit log entry"""
    log_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = ""
    action: str = ""
    resource_type: Optional[ResourceType] = None
    resource_id: str = ""
    result: str = "success"  # success, failure, denied
    ip_address: str = ""
    user_agent: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0


class GovernanceManager(BaseAgent):
    """
    Enterprise Governance & Access Management
    Comprehensive RBAC, policy management, and security governance
    """

    def __init__(self):
        super().__init__(
            name="governance_manager",
            description="Enterprise governance and access management",
            version="4.0.0"
        )

        self.users: Dict[str, User] = {}
        self.roles: Dict[str, Role] = {}
        self.policies: Dict[str, Policy] = {}
        self.audit_logs: List[AuditLog] = []
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

        # Security settings
        self.password_policy = {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "max_age_days": 90,
            "history_count": 12
        }

        self.session_policy = {
            "default_timeout": 3600,
            "max_timeout": 28800,
            "require_mfa": True,
            "max_concurrent_sessions": 3
        }

    async def initialize(self) -> bool:
        """Initialize governance manager"""
        try:
            # Initialize default roles
            await self._initialize_default_roles()

            # Load security policies
            await self._load_security_policies()

            # Setup audit logging
            await self._setup_audit_logging()

            logging.info("Governance Manager initialized")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Governance Manager: {e}")
            return False

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for governance and access control"""
        try:
            governance_events = []

            # Check for access violations
            access_violations = await self._check_access_violations(event)

            # Check for policy violations
            policy_violations = await self._check_policy_violations(event)

            # Log security events
            await self._log_security_event(event)

            # Generate governance events
            if access_violations:
                for violation in access_violations:
                    governance_event = await self._create_access_violation_event(event, violation)
                    governance_events.append(governance_event)

            if policy_violations:
                for violation in policy_violations:
                    policy_event = await self._create_policy_violation_event(event, violation)
                    governance_events.append(policy_event)

            return [event] + governance_events

        except Exception as e:
            logging.error(f"Error processing event for governance: {e}")
            return [event]

    async def authenticate_user(self, username: str, password: str, mfa_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Authenticate user and create session"""
        try:
            # Find user
            user = next((u for u in self.users.values() if u.username == username), None)
            if not user:
                await self._log_audit_event("authentication", "login_failure", details={"reason": "user_not_found", "username": username})
                return None

            # Check account status
            if not user.active or user.account_locked:
                await self._log_audit_event("authentication", "login_failure", user_id=user.user_id, details={"reason": "account_disabled"})
                return None

            # Verify password (simplified - in production use proper hashing)
            if not self._verify_password(password, user):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.account_locked = True
                await self._log_audit_event("authentication", "login_failure", user_id=user.user_id, details={"reason": "invalid_password"})
                return None

            # Verify MFA if required
            if user.mfa_enabled and not self._verify_mfa_token(mfa_token, user):
                await self._log_audit_event("authentication", "login_failure", user_id=user.user_id, details={"reason": "invalid_mfa"})
                return None

            # Create session
            session = await self._create_user_session(user)

            # Update user login info
            user.last_login = datetime.now(timezone.utc)
            user.failed_login_attempts = 0

            await self._log_audit_event("authentication", "login_success", user_id=user.user_id)

            return session

        except Exception as e:
            logging.error(f"Error authenticating user: {e}")
            return None

    async def authorize_action(self, user_id: str, action: str, resource_type: Optional[ResourceType] = None, resource_id: str = "") -> bool:
        """Authorize user action"""
        try:
            user = self.users.get(user_id)
            if not user or not user.active:
                await self._log_audit_event("authorization", "access_denied", user_id=user_id,
                                          details={"reason": "user_not_found", "action": action})
                return False

            # Check permissions
            required_permission = self._map_action_to_permission(action)
            if required_permission and required_permission not in user.permissions:
                await self._log_audit_event("authorization", "access_denied", user_id=user_id,
                                          details={"reason": "insufficient_permissions", "action": action, "required": required_permission.value})
                return False

            # Check resource-level access
            if resource_type:
                access_level = await self._get_user_resource_access(user, resource_type, resource_id)
                required_level = self._get_required_access_level(action)

                if not self._has_sufficient_access(access_level, required_level):
                    await self._log_audit_event("authorization", "access_denied", user_id=user_id,
                                              details={"reason": "insufficient_resource_access", "resource_type": resource_type.value})
                    return False

            # Check policy constraints
            if not await self._check_policy_constraints(user, action, resource_type):
                await self._log_audit_event("authorization", "access_denied", user_id=user_id,
                                          details={"reason": "policy_violation", "action": action})
                return False

            await self._log_audit_event("authorization", "access_granted", user_id=user_id,
                                      details={"action": action, "resource_type": resource_type.value if resource_type else None})
            return True

        except Exception as e:
            logging.error(f"Error authorizing action: {e}")
            return False

    async def _initialize_default_roles(self):
        """Initialize default system roles"""

        # Super Admin - Full system access
        super_admin_role = Role(
            role_id="super_admin",
            name="Super Administrator",
            description="Full system administration access",
            permissions=set(Permission),  # All permissions
            resource_access={rt: AccessLevel.ADMIN for rt in ResourceType}
        )

        # CISO - Executive security oversight
        ciso_role = Role(
            role_id="ciso",
            name="Chief Information Security Officer",
            description="Executive security leadership and oversight",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_EXECUTIVE_REPORTS, Permission.EXPORT_REPORTS,
                Permission.VIEW_INCIDENTS, Permission.COORDINATE_RESPONSE, Permission.APPROVE_RESPONSES,
                Permission.MANAGE_COMPLIANCE, Permission.CONDUCT_ASSESSMENTS, Permission.UPDATE_POLICIES,
                Permission.VIEW_AUDIT_LOGS, Permission.EXPORT_AUDIT_LOGS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.INVESTIGATION: AccessLevel.READ,
                ResourceType.THREAT_INTEL: AccessLevel.READ,
                ResourceType.AUDIT_LOG: AccessLevel.READ,
                ResourceType.REPORT: AccessLevel.ADMIN,
                ResourceType.DASHBOARD: AccessLevel.READ,
                ResourceType.POLICY: AccessLevel.ADMIN
            }
        )

        # SOC Manager - Security operations management
        soc_manager_role = Role(
            role_id="soc_manager",
            name="SOC Manager",
            description="Security Operations Center management",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.CREATE_INCIDENTS,
                Permission.UPDATE_INCIDENTS, Permission.CLOSE_INCIDENTS, Permission.COORDINATE_RESPONSE,
                Permission.APPROVE_RESPONSES, Permission.MANAGE_CONTAINMENT, Permission.VIEW_THREAT_INTEL,
                Permission.VIEW_USERS, Permission.UPDATE_USERS, Permission.CONFIGURE_AGENTS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.ADMIN,
                ResourceType.INVESTIGATION: AccessLevel.WRITE,
                ResourceType.THREAT_INTEL: AccessLevel.WRITE,
                ResourceType.DASHBOARD: AccessLevel.READ,
                ResourceType.SYSTEM_CONFIG: AccessLevel.WRITE
            }
        )

        # Security Analyst - Front-line analysis
        security_analyst_role = Role(
            role_id="security_analyst",
            name="Security Analyst",
            description="Security event analysis and investigation",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.CREATE_INCIDENTS,
                Permission.UPDATE_INCIDENTS, Permission.CREATE_INVESTIGATIONS, Permission.VIEW_INVESTIGATIONS,
                Permission.UPDATE_INVESTIGATIONS, Permission.VIEW_THREAT_INTEL, Permission.UPDATE_THREAT_INTEL,
                Permission.MANAGE_INDICATORS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.WRITE,
                ResourceType.INVESTIGATION: AccessLevel.WRITE,
                ResourceType.THREAT_INTEL: AccessLevel.WRITE,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Incident Responder - Response coordination
        incident_responder_role = Role(
            role_id="incident_responder",
            name="Incident Responder",
            description="Incident response and containment",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.UPDATE_INCIDENTS,
                Permission.EXECUTE_RESPONSE_PLANS, Permission.MANAGE_CONTAINMENT, Permission.VIEW_INVESTIGATIONS,
                Permission.UPDATE_INVESTIGATIONS, Permission.VIEW_THREAT_INTEL
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.WRITE,
                ResourceType.INVESTIGATION: AccessLevel.WRITE,
                ResourceType.THREAT_INTEL: AccessLevel.READ,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Threat Hunter - Proactive threat hunting
        threat_hunter_role = Role(
            role_id="threat_hunter",
            name="Threat Hunter",
            description="Proactive threat hunting and analysis",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.CREATE_INVESTIGATIONS,
                Permission.VIEW_INVESTIGATIONS, Permission.UPDATE_INVESTIGATIONS, Permission.VIEW_THREAT_INTEL,
                Permission.UPDATE_THREAT_INTEL, Permission.MANAGE_INDICATORS, Permission.ACCESS_FORENSICS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.INVESTIGATION: AccessLevel.WRITE,
                ResourceType.THREAT_INTEL: AccessLevel.WRITE,
                ResourceType.EVIDENCE: AccessLevel.WRITE,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Compliance Officer - Regulatory compliance
        compliance_officer_role = Role(
            role_id="compliance_officer",
            name="Compliance Officer",
            description="Regulatory compliance management",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.MANAGE_COMPLIANCE,
                Permission.CONDUCT_ASSESSMENTS, Permission.VIEW_AUDIT_LOGS, Permission.EXPORT_AUDIT_LOGS,
                Permission.UPDATE_POLICIES, Permission.EXPORT_REPORTS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.AUDIT_LOG: AccessLevel.READ,
                ResourceType.POLICY: AccessLevel.WRITE,
                ResourceType.REPORT: AccessLevel.WRITE,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Forensics Analyst - Digital forensics
        forensics_analyst_role = Role(
            role_id="forensics_analyst",
            name="Forensics Analyst",
            description="Digital forensics and evidence analysis",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.VIEW_INVESTIGATIONS,
                Permission.UPDATE_INVESTIGATIONS, Permission.ACCESS_FORENSICS, Permission.VIEW_THREAT_INTEL
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.INVESTIGATION: AccessLevel.WRITE,
                ResourceType.EVIDENCE: AccessLevel.ADMIN,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Auditor - Security auditing
        auditor_role = Role(
            role_id="auditor",
            name="Security Auditor",
            description="Security audit and compliance review",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.VIEW_INVESTIGATIONS,
                Permission.VIEW_AUDIT_LOGS, Permission.EXPORT_AUDIT_LOGS, Permission.CONDUCT_ASSESSMENTS,
                Permission.EXPORT_REPORTS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.INVESTIGATION: AccessLevel.READ,
                ResourceType.AUDIT_LOG: AccessLevel.READ,
                ResourceType.REPORT: AccessLevel.READ,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Read-Only User - Limited access
        read_only_role = Role(
            role_id="read_only_user",
            name="Read-Only User",
            description="Limited read-only access",
            permissions={
                Permission.VIEW_DASHBOARD, Permission.VIEW_INCIDENTS, Permission.VIEW_INVESTIGATIONS
            },
            resource_access={
                ResourceType.INCIDENT: AccessLevel.READ,
                ResourceType.INVESTIGATION: AccessLevel.READ,
                ResourceType.DASHBOARD: AccessLevel.READ
            }
        )

        # Store all roles
        for role in [super_admin_role, ciso_role, soc_manager_role, security_analyst_role,
                    incident_responder_role, threat_hunter_role, compliance_officer_role,
                    forensics_analyst_role, auditor_role, read_only_role]:
            self.roles[role.role_id] = role

    async def _load_security_policies(self):
        """Load security policies"""

        # Password Policy
        password_policy = Policy(
            policy_id="password_policy",
            name="Password Security Policy",
            description="Enterprise password requirements",
            policy_type="security",
            rules=[
                {"type": "min_length", "value": 12},
                {"type": "complexity", "value": "high"},
                {"type": "max_age", "value": 90},
                {"type": "history", "value": 12},
                {"type": "lockout_threshold", "value": 5}
            ],
            applies_to=list(UserRole),
            enforcement_level="enforced"
        )

        # Access Control Policy
        access_policy = Policy(
            policy_id="access_control_policy",
            name="Access Control Policy",
            description="Role-based access control requirements",
            policy_type="access",
            rules=[
                {"type": "require_mfa", "value": True},
                {"type": "session_timeout", "value": 3600},
                {"type": "concurrent_sessions", "value": 3},
                {"type": "privileged_access_approval", "value": True}
            ],
            applies_to=list(UserRole),
            enforcement_level="enforced"
        )

        # Data Classification Policy
        data_policy = Policy(
            policy_id="data_classification_policy",
            name="Data Classification Policy",
            description="Data handling and protection requirements",
            policy_type="compliance",
            rules=[
                {"type": "classify_sensitive_data", "value": True},
                {"type": "encrypt_at_rest", "value": True},
                {"type": "encrypt_in_transit", "value": True},
                {"type": "access_logging", "value": True}
            ],
            applies_to=list(UserRole),
            enforcement_level="enforced"
        )

        # Store policies
        for policy in [password_policy, access_policy, data_policy]:
            self.policies[policy.policy_id] = policy

    async def _setup_audit_logging(self):
        """Setup comprehensive audit logging"""
        pass  # Audit logging setup

    async def _create_user_session(self, user: User) -> Dict[str, Any]:
        """Create authenticated user session"""
        session_id = str(uuid.uuid4())

        # Compile user permissions from roles
        all_permissions = set()
        for role_name in user.roles:
            role = self.roles.get(role_name.value)
            if role:
                all_permissions.update(role.permissions)

        user.permissions = all_permissions

        session = {
            "session_id": session_id,
            "user_id": user.user_id,
            "username": user.username,
            "roles": [r.value for r in user.roles],
            "permissions": [p.value for p in user.permissions],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=user.session_timeout)).isoformat(),
            "mfa_verified": user.mfa_enabled
        }

        self.active_sessions[session_id] = session
        return session

    def _verify_password(self, password: str, user: User) -> bool:
        """Verify user password (simplified implementation)"""
        # In production, use proper password hashing (bcrypt, scrypt, etc.)
        return True  # Simplified for demo

    def _verify_mfa_token(self, token: Optional[str], user: User) -> bool:
        """Verify MFA token (simplified implementation)"""
        # In production, integrate with TOTP/HOTP or SMS/Email
        return token is not None  # Simplified for demo

    def _map_action_to_permission(self, action: str) -> Optional[Permission]:
        """Map action to required permission"""
        action_permission_map = {
            "view_incidents": Permission.VIEW_INCIDENTS,
            "create_incident": Permission.CREATE_INCIDENTS,
            "update_incident": Permission.UPDATE_INCIDENTS,
            "close_incident": Permission.CLOSE_INCIDENTS,
            "delete_incident": Permission.DELETE_INCIDENTS,
            "create_investigation": Permission.CREATE_INVESTIGATIONS,
            "view_investigation": Permission.VIEW_INVESTIGATIONS,
            "update_investigation": Permission.UPDATE_INVESTIGATIONS,
            "execute_response": Permission.EXECUTE_RESPONSE_PLANS,
            "approve_response": Permission.APPROVE_RESPONSES,
            "coordinate_response": Permission.COORDINATE_RESPONSE,
            "view_threat_intel": Permission.VIEW_THREAT_INTEL,
            "update_threat_intel": Permission.UPDATE_THREAT_INTEL,
            "configure_agents": Permission.CONFIGURE_AGENTS,
            "manage_users": Permission.MANAGE_ROLES,
            "view_audit_logs": Permission.VIEW_AUDIT_LOGS,
            "export_audit_logs": Permission.EXPORT_AUDIT_LOGS,
            "manage_compliance": Permission.MANAGE_COMPLIANCE,
            "system_admin": Permission.SYSTEM_ADMINISTRATION
        }

        return action_permission_map.get(action)

    async def _get_user_resource_access(self, user: User, resource_type: ResourceType, resource_id: str) -> AccessLevel:
        """Get user's access level for specific resource"""
        highest_access = AccessLevel.NONE

        for role_name in user.roles:
            role = self.roles.get(role_name.value)
            if role and resource_type in role.resource_access:
                access_level = role.resource_access[resource_type]
                if self._access_level_value(access_level) > self._access_level_value(highest_access):
                    highest_access = access_level

        return highest_access

    def _access_level_value(self, level: AccessLevel) -> int:
        """Get numeric value for access level comparison"""
        level_values = {
            AccessLevel.NONE: 0,
            AccessLevel.READ: 1,
            AccessLevel.WRITE: 2,
            AccessLevel.ADMIN: 3,
            AccessLevel.OWNER: 4
        }
        return level_values.get(level, 0)

    def _get_required_access_level(self, action: str) -> AccessLevel:
        """Get required access level for action"""
        if action.startswith("view_") or action.startswith("read_"):
            return AccessLevel.READ
        elif action.startswith("create_") or action.startswith("update_") or action.startswith("delete_"):
            return AccessLevel.WRITE
        elif action.startswith("manage_") or action.startswith("configure_"):
            return AccessLevel.ADMIN
        else:
            return AccessLevel.READ

    def _has_sufficient_access(self, user_level: AccessLevel, required_level: AccessLevel) -> bool:
        """Check if user has sufficient access level"""
        return self._access_level_value(user_level) >= self._access_level_value(required_level)

    async def _check_policy_constraints(self, user: User, action: str, resource_type: Optional[ResourceType]) -> bool:
        """Check policy constraints for action"""
        # Check applicable policies
        for policy in self.policies.values():
            if not policy.active or policy.enforcement_level == "disabled":
                continue

            # Check if policy applies to user's roles
            if any(role in policy.applies_to for role in user.roles):
                # Apply policy rules
                for rule in policy.rules:
                    if not self._evaluate_policy_rule(rule, user, action, resource_type):
                        return False

        return True

    def _evaluate_policy_rule(self, rule: Dict[str, Any], user: User, action: str, resource_type: Optional[ResourceType]) -> bool:
        """Evaluate individual policy rule"""
        rule_type = rule.get("type")

        if rule_type == "require_mfa" and rule.get("value", False):
            return user.mfa_enabled

        elif rule_type == "privileged_access_approval" and rule.get("value", False):
            privileged_actions = ["delete_incident", "system_admin", "manage_users"]
            if action in privileged_actions:
                # In production, check for approval workflow
                return True  # Simplified

        elif rule_type == "time_based_access":
            # Check time-based access restrictions
            pass

        return True

    async def _check_access_violations(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Check for access control violations"""
        violations = []

        try:
            # Check for unauthorized access patterns
            if event.event_type == "unauthorized_access":
                violations.append({
                    "violation_type": "unauthorized_access",
                    "severity": "high",
                    "description": "Unauthorized access attempt detected"
                })

            elif event.event_type == "privilege_escalation":
                violations.append({
                    "violation_type": "privilege_escalation",
                    "severity": "critical",
                    "description": "Privilege escalation attempt detected"
                })

        except Exception as e:
            logging.error(f"Error checking access violations: {e}")

        return violations

    async def _check_policy_violations(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Check for policy violations"""
        violations = []

        try:
            # Check against security policies
            if event.event_type == "password_policy_violation":
                violations.append({
                    "violation_type": "password_policy",
                    "policy_id": "password_policy",
                    "severity": "medium",
                    "description": "Password policy violation detected"
                })

        except Exception as e:
            logging.error(f"Error checking policy violations: {e}")

        return violations

    async def _log_security_event(self, event: BaseEvent):
        """Log security-relevant events"""
        try:
            if event.event_type in ["authentication", "authorization", "access_denied", "privilege_escalation"]:
                audit_entry = AuditLog(
                    user_id=event.enrichment.get("user_id", ""),
                    action=event.event_type,
                    resource_type=None,
                    resource_id=event.event_id,
                    result="success" if event.risk_score and event.risk_score < 50 else "suspicious",
                    details=event.enrichment
                )
                self.audit_logs.append(audit_entry)

        except Exception as e:
            logging.error(f"Error logging security event: {e}")

    async def _log_audit_event(self, action: str, result: str, user_id: str = "", resource_type: Optional[ResourceType] = None,
                             resource_id: str = "", details: Optional[Dict[str, Any]] = None):
        """Log audit event"""
        try:
            audit_entry = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                result=result,
                details=details or {}
            )
            self.audit_logs.append(audit_entry)

        except Exception as e:
            logging.error(f"Error logging audit event: {e}")

    async def _create_access_violation_event(self, trigger_event: BaseEvent, violation: Dict[str, Any]) -> BaseEvent:
        """Create access violation event"""
        return BaseEvent(
            event_type="access_violation",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.DETECTION_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="governance_manager",
            risk_score=80 if violation["severity"] == "high" else 60,
            enrichment={
                "violation": violation,
                "trigger_event": trigger_event.event_id,
                "remediation_required": True
            }
        )

    async def _create_policy_violation_event(self, trigger_event: BaseEvent, violation: Dict[str, Any]) -> BaseEvent:
        """Create policy violation event"""
        return BaseEvent(
            event_type="policy_violation",
            event_category=EventCategory.FINDINGS,
            event_class=EventClass.COMPLIANCE_FINDING,
            timestamp=datetime.now(timezone.utc),
            source_agent="governance_manager",
            risk_score=70,
            enrichment={
                "violation": violation,
                "trigger_event": trigger_event.event_id,
                "policy_enforcement": True
            }
        )

    async def cleanup(self) -> None:
        """Cleanup governance manager"""
        try:
            # Clear active sessions
            self.active_sessions.clear()
            logging.info("Governance Manager cleanup completed")
        except Exception as e:
            logging.error(f"Error during governance manager cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get governance manager metrics"""
        return {
            **super().get_metrics(),
            "total_users": len(self.users),
            "active_users": len([u for u in self.users.values() if u.active]),
            "total_roles": len(self.roles),
            "active_sessions": len(self.active_sessions),
            "policies_enforced": len([p for p in self.policies.values() if p.enforcement_level == "enforced"]),
            "audit_events_today": len([log for log in self.audit_logs[-1000:]
                                     if log.timestamp.date() == datetime.now().date()]),
            "failed_logins_today": len([log for log in self.audit_logs[-1000:]
                                      if log.action == "authentication" and log.result == "failure"
                                      and log.timestamp.date() == datetime.now().date()])
        }


# Global instance
governance_manager = GovernanceManager()