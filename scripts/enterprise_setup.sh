#!/bin/bash
# SATRIA AI Enterprise Setup Script
# Comprehensive deployment automation for enterprise environments

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTERPRISE_DIR="$PROJECT_ROOT/docker/enterprise"
CONFIG_DIR="$PROJECT_ROOT/config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should not be run as root for security reasons"
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        error_exit "Docker is not installed. Please install Docker first."
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error_exit "Docker Compose is not installed. Please install Docker Compose first."
    fi

    # Check available memory (minimum 16GB recommended)
    total_memory=$(free -g | awk 'NR==2{print $2}')
    if [[ $total_memory -lt 16 ]]; then
        log_warning "System has ${total_memory}GB memory. 16GB+ recommended for enterprise deployment."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Check available disk space (minimum 100GB recommended)
    available_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $available_space -lt 100 ]]; then
        log_warning "Available disk space: ${available_space}GB. 100GB+ recommended for enterprise deployment."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    log_success "System requirements check completed"
}

# Generate secure random passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Generate JWT secret
generate_jwt_secret() {
    openssl rand -hex 32
}

# Generate encryption key
generate_encryption_key() {
    openssl rand -base64 32
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."

    local env_file="$PROJECT_ROOT/.env.enterprise"

    # Check if .env.enterprise already exists
    if [[ -f "$env_file" ]]; then
        log_warning "Enterprise environment file already exists: $env_file"
        read -p "Overwrite existing configuration? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Using existing configuration"
            return 0
        fi
    fi

    # Get OpenRouter API key
    local openrouter_key=""
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        openrouter_key=$(grep "OPENROUTER_API_KEY=" "$PROJECT_ROOT/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    fi

    if [[ -z "$openrouter_key" ]]; then
        echo
        log_info "OpenRouter API key is required for AI functionality"
        read -p "Enter your OpenRouter API key: " -s openrouter_key
        echo
        if [[ -z "$openrouter_key" ]]; then
            error_exit "OpenRouter API key is required"
        fi
    fi

    # Generate secure credentials
    log_info "Generating secure credentials..."

    local db_password=$(generate_password)
    local redis_password=$(generate_password)
    local secret_key=$(generate_password)
    local jwt_secret=$(generate_jwt_secret)
    local encryption_key=$(generate_encryption_key)
    local grafana_password=$(generate_password)

    # Create enterprise environment file
    cat > "$env_file" << EOF
# SATRIA AI Enterprise Environment Configuration
# Generated on $(date)

# Core Configuration
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=info

# Security
SECRET_KEY=$secret_key
JWT_SECRET=$jwt_secret
ENCRYPTION_KEY=$encryption_key

# API Configuration
OPENROUTER_API_KEY=$openrouter_key

# Database
DB_PASSWORD=$db_password
DATABASE_URL=postgresql://satria:$db_password@postgres:5432/satria_enterprise

# Redis
REDIS_PASSWORD=$redis_password
REDIS_URL=redis://:$redis_password@redis-cluster:6379/0

# Monitoring
GRAFANA_PASSWORD=$grafana_password

# Deployment
COMPOSE_PROJECT_NAME=satria-enterprise
COMPOSE_FILE=docker/enterprise/docker-compose.enterprise.yml

# Resource Limits
API_WORKERS=4
AI_WORKERS=2
MAX_CONCURRENT_SESSIONS=100

# Backup Configuration
BACKUP_RETENTION_DAYS=30
BACKUP_ENCRYPTION=true

# Compliance
AUDIT_RETENTION_DAYS=2555
COMPLIANCE_REPORTING=enabled

# Purple Team
MAX_CONCURRENT_EXERCISES=10
EXERCISE_RETENTION_DAYS=365
EOF

    # Set secure permissions
    chmod 600 "$env_file"

    log_success "Environment configuration created: $env_file"
    log_warning "IMPORTANT: Store these credentials securely!"
    echo
    echo "Database Password: $db_password"
    echo "Redis Password: $redis_password"
    echo "Grafana Password: $grafana_password"
    echo
    read -p "Press Enter to continue..." -n 1 -r
    echo
}

# Generate SSL certificates
setup_ssl() {
    log_info "Setting up SSL certificates..."

    local ssl_dir="$ENTERPRISE_DIR/nginx/ssl"
    mkdir -p "$ssl_dir"

    # Check if certificates already exist
    if [[ -f "$ssl_dir/server.crt" && -f "$ssl_dir/server.key" ]]; then
        log_warning "SSL certificates already exist"
        read -p "Generate new certificates? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Using existing SSL certificates"
            return 0
        fi
    fi

    # Get domain information
    local domain="satria-ai.local"
    read -p "Enter your domain name (default: $domain): " input_domain
    if [[ ! -z "$input_domain" ]]; then
        domain="$input_domain"
    fi

    # Generate private key
    openssl genrsa -out "$ssl_dir/server.key" 4096

    # Generate certificate signing request
    openssl req -new -key "$ssl_dir/server.key" -out "$ssl_dir/server.csr" \
        -subj "/C=US/ST=State/L=City/O=SATRIA AI/OU=Enterprise/CN=$domain"

    # Generate self-signed certificate
    openssl x509 -req -days 365 -in "$ssl_dir/server.csr" -signkey "$ssl_dir/server.key" \
        -out "$ssl_dir/server.crt" \
        -extensions v3_req -extfile <(cat << EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = *.${domain}
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
)

    # Set secure permissions
    chmod 600 "$ssl_dir/server.key"
    chmod 644 "$ssl_dir/server.crt"

    # Clean up CSR
    rm -f "$ssl_dir/server.csr"

    log_success "SSL certificates generated for domain: $domain"
}

# Setup nginx configuration
setup_nginx() {
    log_info "Setting up nginx configuration..."

    local nginx_dir="$ENTERPRISE_DIR/nginx"
    mkdir -p "$nginx_dir/logs"

    # Create nginx configuration
    cat > "$nginx_dir/nginx.conf" << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains";

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # Upstream servers
    upstream satria_api {
        least_conn;
        server api-1:8000 max_fails=3 fail_timeout=30s;
        server api-2:8000 max_fails=3 fail_timeout=30s;
        server api-3:8000 max_fails=3 fail_timeout=30s;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # API routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://satria_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        # Health check
        location /health {
            proxy_pass http://satria_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket support for purple team collaboration
        location /ws/ {
            proxy_pass http://satria_api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Static files
        location /static/ {
            alias /app/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Default response
        location / {
            return 200 '{"status":"SATRIA AI Enterprise","version":"2.0.0"}';
            add_header Content-Type application/json;
        }
    }

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$server_name$request_uri;
    }

    # Health check for load balancer
    server {
        listen 80;
        server_name health;
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

    log_success "Nginx configuration created"
}

# Setup monitoring configuration
setup_monitoring() {
    log_info "Setting up monitoring configuration..."

    local monitoring_dir="$ENTERPRISE_DIR/monitoring"
    mkdir -p "$monitoring_dir/grafana/dashboards" "$monitoring_dir/grafana/datasources" "$monitoring_dir/logstash/pipeline" "$monitoring_dir/logstash/config"

    # Prometheus configuration
    cat > "$monitoring_dir/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'satria-api'
    static_configs:
      - targets: ['api-1:8000', 'api-2:8000', 'api-3:8000']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'satria-ai'
    static_configs:
      - targets: ['ai-processor-1:8000', 'ai-processor-2:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-cluster:6379']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']
EOF

    # Grafana datasource
    cat > "$monitoring_dir/grafana/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

    log_success "Monitoring configuration created"
}

# Setup database configuration
setup_database() {
    log_info "Setting up database configuration..."

    local postgres_dir="$ENTERPRISE_DIR/postgres"
    mkdir -p "$postgres_dir/init"

    # PostgreSQL configuration
    cat > "$postgres_dir/postgresql.conf" << 'EOF'
# SATRIA AI Enterprise PostgreSQL Configuration

# Connection settings
listen_addresses = '*'
port = 5432
max_connections = 200

# Memory settings
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 16MB
maintenance_work_mem = 256MB

# WAL settings
wal_level = replica
wal_buffers = 16MB
checkpoint_completion_target = 0.9
max_wal_size = 2GB
min_wal_size = 1GB

# Query planner
random_page_cost = 1.1
effective_io_concurrency = 200

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on

# Statistics
track_activities = on
track_counts = on
track_io_timing = on
track_functions = pl

# Performance
fsync = on
synchronous_commit = on
full_page_writes = on
EOF

    # Database initialization script
    cat > "$postgres_dir/init/01-init-enterprise.sql" << 'EOF'
-- SATRIA AI Enterprise Database Initialization

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create enterprise schemas
CREATE SCHEMA IF NOT EXISTS compliance;
CREATE SCHEMA IF NOT EXISTS governance;
CREATE SCHEMA IF NOT EXISTS purple_team;
CREATE SCHEMA IF NOT EXISTS reporting;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set up permissions
GRANT USAGE ON SCHEMA compliance TO satria;
GRANT USAGE ON SCHEMA governance TO satria;
GRANT USAGE ON SCHEMA purple_team TO satria;
GRANT USAGE ON SCHEMA reporting TO satria;
GRANT USAGE ON SCHEMA audit TO satria;

GRANT CREATE ON SCHEMA compliance TO satria;
GRANT CREATE ON SCHEMA governance TO satria;
GRANT CREATE ON SCHEMA purple_team TO satria;
GRANT CREATE ON SCHEMA reporting TO satria;
GRANT CREATE ON SCHEMA audit TO satria;
EOF

    log_success "Database configuration created"
}

# Build and deploy
deploy_enterprise() {
    log_info "Building and deploying SATRIA AI Enterprise..."

    cd "$PROJECT_ROOT"

    # Load environment
    set -a
    source .env.enterprise
    set +a

    # Build images
    log_info "Building Docker images..."
    docker-compose -f docker/enterprise/docker-compose.enterprise.yml build --no-cache

    # Start services
    log_info "Starting enterprise services..."
    docker-compose -f docker/enterprise/docker-compose.enterprise.yml up -d

    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."

    local max_attempts=60
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        local healthy_services=$(docker-compose -f docker/enterprise/docker-compose.enterprise.yml ps --filter "health=healthy" --format "table {{.Name}}" | grep -c satria || echo 0)
        local total_services=5  # API nodes + AI nodes

        if [[ $healthy_services -eq $total_services ]]; then
            log_success "All services are healthy!"
            break
        fi

        log_info "Waiting for services to be healthy... ($healthy_services/$total_services healthy, attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    if [[ $attempt -gt $max_attempts ]]; then
        log_warning "Not all services became healthy within the timeout period"
        log_info "You can check service status with: docker-compose -f docker/enterprise/docker-compose.enterprise.yml ps"
    fi

    # Run initial database setup
    log_info "Running database initialization..."
    docker-compose -f docker/enterprise/docker-compose.enterprise.yml exec -T api-1 python -c "
import sys
sys.path.append('/app/src')
from satria.core.database import init_db
from satria.enterprise.compliance import compliance_engine
from satria.enterprise.governance import governance_manager
init_db()
compliance_engine.initialize_database()
governance_manager.initialize_database()
print('Database initialization completed')
"

    log_success "SATRIA AI Enterprise deployment completed!"
}

# Display final information
show_deployment_info() {
    log_info "SATRIA AI Enterprise Deployment Information"
    echo
    echo "🌐 Access URLs:"
    echo "   • Main API: https://localhost/api/v1/"
    echo "   • Health Check: https://localhost/health"
    echo "   • Grafana: http://localhost:3000 (admin / check .env.enterprise for password)"
    echo "   • Kibana: http://localhost:5601"
    echo
    echo "📁 Important Files:"
    echo "   • Environment: .env.enterprise"
    echo "   • SSL Certificates: docker/enterprise/nginx/ssl/"
    echo "   • Logs: Use 'docker-compose logs' to view application logs"
    echo
    echo "🔧 Management Commands:"
    echo "   • Start: docker-compose -f docker/enterprise/docker-compose.enterprise.yml up -d"
    echo "   • Stop: docker-compose -f docker/enterprise/docker-compose.enterprise.yml down"
    echo "   • Status: docker-compose -f docker/enterprise/docker-compose.enterprise.yml ps"
    echo "   • Logs: docker-compose -f docker/enterprise/docker-compose.enterprise.yml logs -f"
    echo
    echo "🔐 Security Notes:"
    echo "   • All credentials are stored in .env.enterprise"
    echo "   • SSL certificates are self-signed (replace with CA-signed for production)"
    echo "   • Change default passwords before production use"
    echo
    echo "📊 Monitoring:"
    echo "   • Prometheus metrics are available for all services"
    echo "   • Grafana dashboards are pre-configured"
    echo "   • ELK stack is set up for log aggregation"
    echo
    log_success "Enterprise deployment is ready!"
}

# Main execution
main() {
    echo "================================================"
    echo "SATRIA AI Enterprise Setup"
    echo "Version 2.0.0 - Phase 4 Enterprise Edition"
    echo "================================================"
    echo

    check_root
    check_requirements
    setup_environment
    setup_ssl
    setup_nginx
    setup_monitoring
    setup_database
    deploy_enterprise
    show_deployment_info

    echo
    log_success "SATRIA AI Enterprise setup completed successfully!"
    echo "Thank you for choosing SATRIA AI Enterprise Edition."
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi