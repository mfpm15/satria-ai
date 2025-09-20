# SATRIA AI Enterprise Edition Dockerfile
# Multi-stage build for production-ready deployment

# Stage 1: Base image with security hardening
FROM python:3.11-slim-bookworm as base

# Security: Create non-root user
RUN groupadd -r satria && useradd -r -g satria satria

# Security: Update system packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Security: Remove unnecessary packages and files
RUN apt-get autoremove -y && \
    rm -rf /var/cache/apt/* /tmp/* /var/tmp/*

# Stage 2: Dependencies installation
FROM base as dependencies

# Install system dependencies for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==1.7.1

# Copy dependency files
WORKDIR /app
COPY pyproject.toml poetry.lock ./

# Configure Poetry
RUN poetry config virtualenvs.create false && \
    poetry config virtualenvs.in-project false

# Install dependencies
RUN poetry install --only=main --no-dev --no-interaction --no-ansi

# Stage 3: Application image
FROM base as application

# Copy installed packages from dependencies stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Create application directories
WORKDIR /app
RUN mkdir -p /app/data /app/logs /app/config /app/uploads && \
    chown -R satria:satria /app

# Copy application code
COPY --chown=satria:satria src/ /app/src/
COPY --chown=satria:satria config/ /app/config/
COPY --chown=satria:satria scripts/ /app/scripts/

# Copy entrypoint script
COPY --chown=satria:satria docker/enterprise/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Security: Set file permissions
RUN find /app -type f -exec chmod 644 {} \; && \
    find /app -type d -exec chmod 755 {} \; && \
    chmod +x /app/entrypoint.sh /app/scripts/*.sh

# Health check script
COPY --chown=satria:satria docker/enterprise/healthcheck.py /app/healthcheck.py

# Environment configuration
ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Security: Switch to non-root user
USER satria

# Expose application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python /app/healthcheck.py

# Default command
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "satria.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# Stage 4: AI Processing image
FROM application as ai-processing

USER root

# Install AI/ML dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libblas3 \
    liblapack3 \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Install GPU support (if available)
RUN pip install --no-cache-dir \
    torch \
    transformers \
    accelerate \
    bitsandbytes

# Switch back to non-root user
USER satria

# Override command for AI processing
CMD ["uvicorn", "satria.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

# Stage 5: Development image
FROM application as development

USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    ruff \
    mypy \
    pre-commit

# Switch back to non-root user
USER satria

# Override for development
CMD ["uvicorn", "satria.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Labels for enterprise compliance
LABEL maintainer="SATRIA AI Team <team@satria-ai.com>" \
      version="2.0.0" \
      description="SATRIA AI Enterprise Cybersecurity Platform" \
      vendor="SATRIA AI" \
      licenses="Enterprise License" \
      build-date="2024-01-20" \
      vcs-url="https://github.com/satria-ai/platform" \
      security.scan="enabled" \
      compliance.frameworks="SOC2,ISO27001,GDPR" \
      deployment.tier="enterprise"