"""
SATRIA AI API Security
Authentication and authorization for SATRIA API
"""

import asyncio
import logging
import hashlib
import secrets
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status

from satria.core.config import settings


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
JWT_ALGORITHM = settings.jwt_algorithm
SECRET_KEY = settings.secret_key
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes


class SecurityManager:
    """SATRIA Security Manager"""

    def __init__(self):
        self.logger = logging.getLogger("satria.security")

        # In-memory stores (in production, use proper database)
        self.users: Dict[str, Dict[str, Any]] = {}
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.revoked_tokens: set = set()

        # Initialize default users
        self._initialize_default_users()

    def _initialize_default_users(self):
        """Initialize default users for development"""
        default_users = [
            {
                "username": "admin",
                "password": "satria123",  # In production, use strong passwords
                "roles": ["admin", "analyst", "red_team", "purple_team", "planner", "planner_approver"],
                "permissions": ["*"]
            },
            {
                "username": "analyst",
                "password": "analyst123",
                "roles": ["analyst"],
                "permissions": ["read_events", "read_graph", "read_metrics"]
            },
            {
                "username": "red_team",
                "password": "redteam123",
                "roles": ["red_team", "purple_team"],
                "permissions": ["read_events", "execute_tools", "create_sessions"]
            }
        ]

        for user_data in default_users:
            self.create_user(
                username=user_data["username"],
                password=user_data["password"],
                roles=user_data["roles"],
                permissions=user_data["permissions"]
            )

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

    def create_user(self, username: str, password: str, roles: List[str],
                   permissions: List[str]) -> Dict[str, Any]:
        """Create new user"""
        if username in self.users:
            raise ValueError(f"User {username} already exists")

        user_data = {
            "username": username,
            "password_hash": self.hash_password(password),
            "roles": roles,
            "permissions": permissions,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "active": True
        }

        self.users[username] = user_data
        self.logger.info(f"Created user: {username}")

        return {
            "username": username,
            "roles": roles,
            "permissions": permissions,
            "created_at": user_data["created_at"]
        }

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username/password"""
        user = self.users.get(username)

        if not user or not user["active"]:
            return None

        if not self.verify_password(password, user["password_hash"]):
            return None

        # Update last login
        user["last_login"] = datetime.utcnow()

        return {
            "username": user["username"],
            "roles": user["roles"],
            "permissions": user["permissions"],
            "last_login": user["last_login"]
        }

    def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = {
            "sub": user_data["username"],
            "roles": user_data["roles"],
            "permissions": user_data["permissions"],
            "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.utcnow(),
            "iss": "satria-ai"
        }

        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and return user data"""
        try:
            # Check if token is revoked
            if token in self.revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )

            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            username: str = payload.get("sub")

            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: missing subject"
                )

            # Verify user still exists and is active
            user = self.users.get(username)
            if not user or not user["active"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            return {
                "username": username,
                "roles": payload.get("roles", []),
                "permissions": payload.get("permissions", []),
                "exp": payload.get("exp"),
                "iat": payload.get("iat")
            }

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

    def revoke_token(self, token: str) -> bool:
        """Revoke JWT token"""
        self.revoked_tokens.add(token)

        # Clean old revoked tokens periodically
        if len(self.revoked_tokens) > 10000:
            # Keep only recent tokens (simplified cleanup)
            self.revoked_tokens = set(list(self.revoked_tokens)[-5000:])

        return True

    def create_api_key(self, name: str, permissions: List[str],
                      expires_in_days: Optional[int] = None) -> Dict[str, Any]:
        """Create API key"""
        api_key = secrets.token_urlsafe(32)
        key_id = hashlib.sha256(api_key.encode()).hexdigest()[:16]

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        key_data = {
            "key_id": key_id,
            "name": name,
            "permissions": permissions,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "active": True,
            "last_used": None
        }

        self.api_keys[api_key] = key_data

        return {
            "key_id": key_id,
            "api_key": api_key,  # Only returned once
            "name": name,
            "permissions": permissions,
            "created_at": key_data["created_at"],
            "expires_at": expires_at
        }

    def verify_api_key(self, api_key: str) -> Dict[str, Any]:
        """Verify API key and return associated data"""
        key_data = self.api_keys.get(api_key)

        if not key_data or not key_data["active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

        # Check expiration
        if key_data["expires_at"] and datetime.utcnow() > key_data["expires_at"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key expired"
            )

        # Update last used
        key_data["last_used"] = datetime.utcnow()

        return {
            "key_id": key_data["key_id"],
            "name": key_data["name"],
            "permissions": key_data["permissions"]
        }

    def check_permission(self, user_permissions: List[str], required_permission: str) -> bool:
        """Check if user has required permission"""
        # Admin wildcard
        if "*" in user_permissions:
            return True

        # Exact match
        if required_permission in user_permissions:
            return True

        # Wildcard permissions (e.g., "read_*" matches "read_events")
        for permission in user_permissions:
            if permission.endswith("*"):
                prefix = permission[:-1]
                if required_permission.startswith(prefix):
                    return True

        return False

    def check_role(self, user_roles: List[str], required_role: str) -> bool:
        """Check if user has required role"""
        return required_role in user_roles or "admin" in user_roles

    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information"""
        user = self.users.get(username)
        if not user:
            return None

        return {
            "username": user["username"],
            "roles": user["roles"],
            "permissions": user["permissions"],
            "created_at": user["created_at"],
            "last_login": user["last_login"],
            "active": user["active"]
        }

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users (admin only)"""
        return [
            {
                "username": user["username"],
                "roles": user["roles"],
                "permissions": user["permissions"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "active": user["active"]
            }
            for user in self.users.values()
        ]

    def deactivate_user(self, username: str) -> bool:
        """Deactivate user"""
        user = self.users.get(username)
        if not user:
            return False

        user["active"] = False
        self.logger.info(f"Deactivated user: {username}")
        return True

    def activate_user(self, username: str) -> bool:
        """Activate user"""
        user = self.users.get(username)
        if not user:
            return False

        user["active"] = True
        self.logger.info(f"Activated user: {username}")
        return True


# Global security manager instance
security_manager = SecurityManager()


# Authentication functions for FastAPI dependency injection
async def verify_token(token: str) -> Dict[str, Any]:
    """Verify JWT token (async wrapper)"""
    return security_manager.verify_token(token)


async def verify_api_key(api_key: str) -> Dict[str, Any]:
    """Verify API key (async wrapper)"""
    return security_manager.verify_api_key(api_key)


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract user info from kwargs (injected by FastAPI)
            user_info = kwargs.get('user_info')
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            if not security_manager.check_permission(user_info.get("permissions", []), permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required"
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(role: str):
    """Decorator to require specific role"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract user info from kwargs (injected by FastAPI)
            user_info = kwargs.get('user_info')
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            if not security_manager.check_role(user_info.get("roles", []), role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' required"
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Rate limiting (simple in-memory implementation)
class RateLimiter:
    """Simple rate limiter"""

    def __init__(self):
        self.requests: Dict[str, List[datetime]] = {}

    def is_allowed(self, key: str, max_requests: int = 100, window_seconds: int = 3600) -> bool:
        """Check if request is allowed under rate limit"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        # Initialize or clean old requests
        if key not in self.requests:
            self.requests[key] = []

        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > window_start
        ]

        # Check limit
        if len(self.requests[key]) >= max_requests:
            return False

        # Add current request
        self.requests[key].append(now)
        return True


# Global rate limiter
rate_limiter = RateLimiter()