# SATRIA AI - Development Makefile
.PHONY: help setup install dev test lint format clean build run stop logs

# Default target
help:
	@echo "🛡️  SATRIA AI - Smart Autonomous Threat Response & Intelligence Agent"
	@echo ""
	@echo "Available commands:"
	@echo "  setup    - Initial project setup (install poetry, dependencies)"
	@echo "  install  - Install Python dependencies"
	@echo "  dev      - Start development environment"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run code linting"
	@echo "  format   - Format code with black and isort"
	@echo "  clean    - Clean temporary files and caches"
	@echo "  build    - Build Docker containers"
	@echo "  run      - Start SATRIA AI system"
	@echo "  stop     - Stop all services"
	@echo "  logs     - Show service logs"

# Initial setup
setup:
	@echo "🚀 Setting up SATRIA AI development environment..."
	curl -sSL https://install.python-poetry.org | python3 -
	poetry install
	poetry run pre-commit install
	cp .env.example .env
	@echo "✅ Setup complete! Run 'make dev' to start development."

# Install dependencies
install:
	poetry install

# Development environment
dev:
	@echo "🔧 Starting development environment..."
	docker-compose -f docker-compose.dev.yml up -d
	poetry run uvicorn satria.api.main:app --reload --host 0.0.0.0 --port 8000

# Run tests
test:
	@echo "🧪 Running tests..."
	poetry run pytest

# Linting
lint:
	@echo "🔍 Running linters..."
	poetry run flake8 src/satria tests/
	poetry run mypy src/satria/
	poetry run bandit -r src/satria/

# Format code
format:
	@echo "🎨 Formatting code..."
	poetry run black src/satria tests/
	poetry run isort src/satria tests/

# Clean temporary files
clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".pytest_cache" -delete
	find . -type f -name ".coverage" -delete
	rm -rf dist/ build/ *.egg-info/

# Build containers
build:
	@echo "🐳 Building Docker containers..."
	docker-compose build

# Run production
run:
	@echo "🛡️  Starting SATRIA AI system..."
	docker-compose up -d
	@echo "✅ SATRIA AI is running!"
	@echo "   Dashboard: http://localhost:8080"
	@echo "   API: http://localhost:8000"
	@echo "   Grafana: http://localhost:3000"

# Stop services
stop:
	@echo "⏹️  Stopping SATRIA AI..."
	docker-compose down

# Show logs
logs:
	docker-compose logs -f

# Database migrations
migrate:
	poetry run alembic upgrade head

# Generate new migration
migration:
	poetry run alembic revision --autogenerate -m "$(msg)"

# Reset database
db-reset:
	docker-compose down -v
	docker-compose up -d postgres neo4j
	sleep 10
	make migrate

# Quick development cycle
quick: format lint test