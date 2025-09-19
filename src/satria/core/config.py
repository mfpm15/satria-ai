"""
SATRIA AI Configuration Management
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """SATRIA AI Configuration Settings"""

    # Environment
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    secret_key: str = Field(env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")

    # Database URLs
    postgres_url: str = Field(env="POSTGRES_URL")
    neo4j_url: str = Field(env="NEO4J_URL")
    redis_url: str = Field(env="REDIS_URL")
    influxdb_url: str = Field(env="INFLUXDB_URL")
    influxdb_token: str = Field(env="INFLUXDB_TOKEN")
    influxdb_org: str = Field(env="INFLUXDB_ORG")
    influxdb_bucket: str = Field(env="INFLUXDB_BUCKET")

    # Message Brokers
    kafka_bootstrap_servers: str = Field(env="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic_prefix: str = Field(default="satria", env="KAFKA_TOPIC_PREFIX")

    # Vector Store
    chroma_url: str = Field(env="CHROMA_URL")
    chroma_collection_name: str = Field(default="satria_kb", env="CHROMA_COLLECTION_NAME")

    # AI Models - OpenRouter.ai Integration
    openrouter_api_key: str = Field(default="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", env="OPENROUTER_API_KEY")
    openrouter_base_url: str = Field(default="https://openrouter.ai/api/v1", env="OPENROUTER_BASE_URL")
    openrouter_model: str = Field(default="openrouter/sonoma-sky-alpha", env="OPENROUTER_MODEL")
    openrouter_site_url: str = Field(default="https://github.com/mfpm15/satria-ai", env="OPENROUTER_SITE_URL")
    openrouter_site_name: str = Field(default="SATRIA AI", env="OPENROUTER_SITE_NAME")

    # Legacy AI Models (fallback)
    ollama_url: str = Field(default="http://localhost:11434", env="OLLAMA_URL")
    default_llm_model: str = Field(default="llama3.1:8b", env="DEFAULT_LLM_MODEL")
    embedding_model: str = Field(default="sentence-transformers/all-MiniLM-L6-v2", env="EMBEDDING_MODEL")

    # External Integrations - EDR
    crowdstrike_client_id: Optional[str] = Field(default=None, env="CROWDSTRIKE_CLIENT_ID")
    crowdstrike_client_secret: Optional[str] = Field(default=None, env="CROWDSTRIKE_CLIENT_SECRET")
    defender_tenant_id: Optional[str] = Field(default=None, env="DEFENDER_TENANT_ID")
    defender_client_id: Optional[str] = Field(default=None, env="DEFENDER_CLIENT_ID")
    defender_client_secret: Optional[str] = Field(default=None, env="DEFENDER_CLIENT_SECRET")

    # SIEM
    elastic_url: Optional[str] = Field(default=None, env="ELASTIC_URL")
    elastic_username: Optional[str] = Field(default=None, env="ELASTIC_USERNAME")
    elastic_password: Optional[str] = Field(default=None, env="ELASTIC_PASSWORD")
    splunk_url: Optional[str] = Field(default=None, env="SPLUNK_URL")
    splunk_token: Optional[str] = Field(default=None, env="SPLUNK_TOKEN")

    # Email Security
    office365_tenant_id: Optional[str] = Field(default=None, env="OFFICE365_TENANT_ID")
    office365_client_id: Optional[str] = Field(default=None, env="OFFICE365_CLIENT_ID")
    office365_client_secret: Optional[str] = Field(default=None, env="OFFICE365_CLIENT_SECRET")

    # Cloud Security
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    azure_subscription_id: Optional[str] = Field(default=None, env="AZURE_SUBSCRIPTION_ID")
    azure_tenant_id: Optional[str] = Field(default=None, env="AZURE_TENANT_ID")
    gcp_project_id: Optional[str] = Field(default=None, env="GCP_PROJECT_ID")
    gcp_service_account_key: Optional[str] = Field(default=None, env="GCP_SERVICE_ACCOUNT_KEY")

    # Threat Intelligence
    misp_url: Optional[str] = Field(default=None, env="MISP_URL")
    misp_api_key: Optional[str] = Field(default=None, env="MISP_API_KEY")
    opencti_url: Optional[str] = Field(default=None, env="OPENCTI_URL")
    opencti_token: Optional[str] = Field(default=None, env="OPENCTI_TOKEN")

    # Monitoring
    prometheus_url: str = Field(default="http://localhost:9090", env="PROMETHEUS_URL")
    grafana_url: str = Field(default="http://localhost:3000", env="GRAFANA_URL")
    grafana_api_key: Optional[str] = Field(default=None, env="GRAFANA_API_KEY")

    # Notification
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    teams_webhook_url: Optional[str] = Field(default=None, env="TEAMS_WEBHOOK_URL")
    email_smtp_server: Optional[str] = Field(default=None, env="EMAIL_SMTP_SERVER")
    email_smtp_port: int = Field(default=587, env="EMAIL_SMTP_PORT")
    email_username: Optional[str] = Field(default=None, env="EMAIL_USERNAME")
    email_password: Optional[str] = Field(default=None, env="EMAIL_PASSWORD")

    # Security
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    hash_algorithm: str = Field(default="bcrypt", env="HASH_ALGORITHM")
    vault_url: Optional[str] = Field(default=None, env="VAULT_URL")
    vault_token: Optional[str] = Field(default=None, env="VAULT_TOKEN")

    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(default=3600, env="RATE_LIMIT_PERIOD")

    # Caching
    cache_ttl: int = Field(default=3600, env="CACHE_TTL")
    redis_cache_prefix: str = Field(default="satria:cache", env="REDIS_CACHE_PREFIX")

    # Audit Logging
    audit_log_retention_days: int = Field(default=365, env="AUDIT_LOG_RETENTION_DAYS")
    immutable_storage_enabled: bool = Field(default=True, env="IMMUTABLE_STORAGE_ENABLED")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()