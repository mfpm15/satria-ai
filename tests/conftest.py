"""
Pytest configuration and fixtures for SATRIA AI tests
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, AsyncMock

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


@pytest.fixture
def mock_database():
    """Mock database connection"""
    mock_db = Mock()
    mock_db.connect = AsyncMock()
    mock_db.close = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_db.fetch = AsyncMock()
    return mock_db


@pytest.fixture
def mock_redis():
    """Mock Redis connection"""
    mock_redis = Mock()
    mock_redis.ping = AsyncMock(return_value=True)
    mock_redis.get = AsyncMock()
    mock_redis.set = AsyncMock()
    mock_redis.delete = AsyncMock()
    return mock_redis


@pytest.fixture
def mock_openrouter_client():
    """Mock OpenRouter API client"""
    mock_client = Mock()
    mock_client.chat = AsyncMock()
    mock_client.completions = AsyncMock()
    return mock_client


@pytest.fixture
def sample_threat_data():
    """Sample threat intelligence data for testing"""
    return {
        "threat_id": "threat_001",
        "type": "malware",
        "severity": "high",
        "indicators": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "confidence": 0.9
            },
            {
                "type": "hash",
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "confidence": 0.8
            }
        ],
        "timestamp": "2024-01-20T10:00:00Z"
    }


@pytest.fixture
def sample_security_event():
    """Sample security event for testing"""
    return {
        "event_id": "event_001",
        "source": "endpoint_detection",
        "event_type": "suspicious_activity",
        "severity": "medium",
        "timestamp": "2024-01-20T10:05:00Z",
        "details": {
            "process": "suspicious.exe",
            "pid": 1234,
            "user": "test_user",
            "host": "test_host"
        }
    }


@pytest.fixture
def mock_environment_variables(monkeypatch):
    """Set up test environment variables"""
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/test_db")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test_api_key")
    monkeypatch.setenv("SECRET_KEY", "test_secret_key")
    monkeypatch.setenv("JWT_SECRET", "test_jwt_secret")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Configure pytest-asyncio
pytest_plugins = ['pytest_asyncio']