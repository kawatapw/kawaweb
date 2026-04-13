.PHONY: help install install-dev sync clean test lint format type-check security-check check-all run

# Default target
help:
	@echo "Available commands:"
	@echo "  make install        - Install production dependencies"
	@echo "  make install-dev    - Install development dependencies"
	@echo "  make sync           - Sync environment with pyproject.toml"
	@echo "  make clean          - Clean cache and temporary files"
	@echo "  make test           - Run tests with pytest"
	@echo "  make test-cov       - Run tests with coverage report"
	@echo "  make lint           - Run ruff linter"
	@echo "  make format         - Format code with black and ruff"
	@echo "  make format-check   - Check formatting without modifying"
	@echo "  make type-check     - Run ty type checker (primary - ultra fast Rust-based)"
	@echo "  make type-check2    - Run mypy type checker (fallback)"
	@echo "  make type-check3    - Run pyright type checker (alternative)"
	@echo "  make security-check - Run bandit security scanner"
	@echo "  make imports        - Sort imports with isort"
	@echo "  make imports-check  - Check import sorting"
	@echo "  make autoflake      - Remove unused imports"
	@echo "  make check-all      - Run all checks (lint, format, type, security)"
	@echo "  make run            - Run the application"
	@echo "  make lock           - Update uv.lock file"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-up      - Start Docker containers"
	@echo "  make docker-down    - Stop Docker containers"

# Install production dependencies (creates .venv if needed)
install:
	@if [ ! -d ".venv" ]; then uv venv; fi
	uv pip install -r pyproject.toml

# Install development dependencies
install-dev:
	@if [ ! -d ".venv" ]; then uv venv; fi
	uv pip install -r pyproject.toml --extra dev

# Sync environment with pyproject.toml
sync:
	uv sync --all-extras

# Clean cache and temporary files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.pyd" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache 2>/dev/null || true
	rm -rf htmlcov .coverage coverage.xml 2>/dev/null || true
	rm -rf dist build *.egg-info 2>/dev/null || true
	@echo "Cleaned temporary files"

# Run tests with pytest
test:
	uv run pytest -v

# Run tests with coverage report
test-cov:
	uv run pytest -v --cov=. --cov-report=html --cov-report=term

# Run ruff linter
lint:
	uv run ruff check . --fix

# Format code with black and ruff
format:
	uv run black .
	uv run ruff check . --fix

# Check formatting without modifying
format-check:
	uv run black . --check
	uv run ruff check .

# Run ty type checker (primary)
type-check:
	uv run ty check . --exclude .venv

# Run mypy type checker (fallback)
type-check2:
	uv run mypy .

# Run pyright type checker (alternative)
type-check3:
	uv run pyright .

# Run bandit security scanner
security-check:
	uv run bandit -r . -ll

# Sort imports with isort
imports:
	uv run isort .

# Check import sorting
imports-check:
	uv run isort . --check-only

# Remove unused imports
autoflake:
	uv run autoflake -r -i --remove-all-unused-imports .

# Run all checks
check-all: lint format-check type-check security-check test
	@echo "All checks completed!"

# Run the application
run:
	uv run python main.py

# Update uv.lock file
lock:
	uv lock

# Build Docker image
docker-build:
	docker build -t kawaweb .

# Start Docker containers
docker-up:
	docker-compose up -d

# Stop Docker containers
docker-down:
	docker-compose down

# Pre-commit checks (run before committing)
pre-commit: lint format-check type-check
	@echo "Pre-commit checks passed!"