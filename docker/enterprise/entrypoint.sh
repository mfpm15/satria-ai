#!/bin/bash
# SATRIA AI Enterprise Entrypoint Script
# Handles initialization, configuration, and startup for enterprise deployment

set -euo pipefail

# Configuration
APP_DIR="/app"
LOG_DIR="/app/logs"
DATA_DIR="/app/data"
CONFIG_DIR="/app/config"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_DIR}/startup.log"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    mkdir -p "${LOG_DIR}" "${DATA_DIR}" "${CONFIG_DIR}/ssl" "${DATA_DIR}/uploads" "${DATA_DIR}/cache"

    # Set proper permissions
    chmod 755 "${LOG_DIR}" "${DATA_DIR}" "${CONFIG_DIR}"
    chmod 700 "${CONFIG_DIR}/ssl"
}

# Environment validation
validate_environment() {
    log "Validating environment configuration..."

    # Required environment variables
    local required_vars=(
        "DATABASE_URL"
        "REDIS_URL"
        "OPENROUTER_API_KEY"
        "SECRET_KEY"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error_exit "Required environment variable $var is not set"
        fi
    done

    # Validate database connectivity
    log "Testing database connectivity..."
    python -c "
import os
import psycopg2
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
    exit(1)
" || error_exit "Database connectivity check failed"

    # Validate Redis connectivity
    log "Testing Redis connectivity..."
    python -c "
import os
import redis
try:
    r = redis.from_url(os.environ['REDIS_URL'])
    r.ping()
    print('Redis connection successful')
except Exception as e:
    print(f'Redis connection failed: {e}')
    exit(1)
" || error_exit "Redis connectivity check failed"
}

# Database initialization
initialize_database() {
    log "Initializing database..."

    # Run database migrations
    python -c "
import sys
sys.path.append('/app/src')
from satria.core.database import init_db
from satria.enterprise.compliance import compliance_engine
from satria.enterprise.governance import governance_manager

# Initialize core database
init_db()

# Initialize enterprise modules
compliance_engine.initialize_database()
governance_manager.initialize_database()

print('Database initialization completed')
" || error_exit "Database initialization failed"
}

# Security configuration
setup_security() {
    log "Setting up security configuration..."

    # Generate SSL certificates if not provided
    if [[ ! -f "${CONFIG_DIR}/ssl/server.crt" ]]; then
        log "Generating self-signed SSL certificates..."
        openssl req -x509 -newkey rsa:4096 -keyout "${CONFIG_DIR}/ssl/server.key" \
                   -out "${CONFIG_DIR}/ssl/server.crt" -days 365 -nodes \
                   -subj "/C=US/ST=State/L=City/O=SATRIA AI/CN=satria-ai.local" \
                   2>/dev/null || log "Warning: SSL certificate generation failed"
        chmod 600 "${CONFIG_DIR}/ssl/server.key"
        chmod 644 "${CONFIG_DIR}/ssl/server.crt"
    fi

    # Set secure file permissions
    find "${APP_DIR}" -name "*.py" -exec chmod 644 {} \;
    find "${APP_DIR}" -name "*.sh" -exec chmod 755 {} \;

    # Validate security configuration
    python -c "
import sys
sys.path.append('/app/src')
from satria.core.security import validate_security_config
if not validate_security_config():
    print('Security configuration validation failed')
    exit(1)
print('Security configuration validated')
" || error_exit "Security configuration validation failed"
}

# Performance optimization
optimize_performance() {
    log "Applying performance optimizations..."

    # Set optimal Python settings
    export PYTHONOPTIMIZE=2
    export PYTHONHASHSEED=random

    # Configure garbage collection
    export PYTHONGC=1

    # Warm up application cache
    python -c "
import sys
sys.path.append('/app/src')
from satria.core.cache import warm_cache
warm_cache()
print('Cache warming completed')
" || log "Warning: Cache warming failed"
}

# Health check setup
setup_health_checks() {
    log "Setting up health checks..."

    # Create health check endpoint test
    python -c "
import sys
sys.path.append('/app/src')
from satria.api.health import health_check
result = health_check()
if not result.get('healthy', False):
    print('Health check failed')
    exit(1)
print('Health check setup completed')
" || error_exit "Health check setup failed"
}

# Monitoring setup
setup_monitoring() {
    log "Setting up monitoring..."

    # Initialize metrics collection
    python -c "
import sys
sys.path.append('/app/src')
from satria.core.monitoring import init_monitoring
init_monitoring()
print('Monitoring initialization completed')
" || log "Warning: Monitoring setup failed"

    # Start background monitoring tasks
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]]; then
        log "Starting background monitoring..."
        python -c "
import sys
sys.path.append('/app/src')
from satria.core.monitoring import start_background_monitoring
start_background_monitoring()
" &
    fi
}

# Compliance initialization
setup_compliance() {
    log "Setting up compliance framework..."

    python -c "
import sys
sys.path.append('/app/src')
from satria.enterprise.compliance import compliance_engine
from satria.enterprise.governance import governance_manager

# Initialize compliance frameworks
compliance_engine.load_frameworks()
governance_manager.load_policies()

print('Compliance framework initialization completed')
" || error_exit "Compliance setup failed"
}

# Purple team setup
setup_purple_team() {
    log "Setting up purple team validation system..."

    python -c "
import sys
sys.path.append('/app/src')
from satria.enterprise.purple_team import purple_team_validator
from satria.enterprise.purple_team import exercise_manager

# Initialize purple team components
purple_team_validator.initialize()
exercise_manager._initialize_default_scenarios()

print('Purple team system initialization completed')
" || error_exit "Purple team setup failed"
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."

    # Stop background processes
    jobs -p | xargs -r kill

    # Cleanup temporary files
    find /tmp -name "satria-*" -type f -delete 2>/dev/null || true

    log "Cleanup completed"
}

# Signal handlers
trap cleanup EXIT TERM INT

# Main initialization sequence
main() {
    log "Starting SATRIA AI Enterprise initialization..."
    log "Version: $(cat /app/VERSION 2>/dev/null || echo 'Unknown')"
    log "Build: $(cat /app/BUILD_INFO 2>/dev/null || echo 'Unknown')"

    # Pre-flight checks
    log "Running pre-flight checks..."

    # Check if running as non-root user
    if [[ $EUID -eq 0 ]]; then
        error_exit "Application should not run as root user"
    fi

    # Check available disk space
    available_space=$(df "${DATA_DIR}" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB in KB
        error_exit "Insufficient disk space available"
    fi

    # Initialize components
    create_directories
    validate_environment
    setup_security
    optimize_performance

    # Database and cache
    initialize_database

    # Enterprise features
    setup_compliance
    setup_purple_team

    # Monitoring and health checks
    setup_health_checks
    setup_monitoring

    log "SATRIA AI Enterprise initialization completed successfully!"
    log "Starting application with command: $*"

    # Execute the main command
    exec "$@"
}

# Handle different startup modes
case "${1:-}" in
    "migrate")
        log "Running database migrations only..."
        initialize_database
        log "Migration completed"
        exit 0
        ;;
    "check")
        log "Running configuration check only..."
        create_directories
        validate_environment
        setup_security
        log "Configuration check completed"
        exit 0
        ;;
    "shell")
        log "Starting interactive shell..."
        exec /bin/bash
        ;;
    *)
        # Normal startup
        main "$@"
        ;;
esac