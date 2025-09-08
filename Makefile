# Makefile for pfSense CLI Tool

.PHONY: help install install-dev test lint format type-check clean build docs docker

# Default help command
help:
	@echo "Available commands:"
	@echo "  install      Install the package for production use"
	@echo "  install-dev  Install the package with development dependencies"
	@echo "  test         Run all tests"
	@echo "  test-unit    Run unit tests only"
	@echo "  test-integration  Run integration tests only"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run mypy type checking"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build distribution packages"
	@echo "  docs         Build documentation"
	@echo "  docker       Build Docker image"
	@echo "  example      Run example commands"

# Installation commands
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,docs]"

# Testing commands
test:
	pytest -v --cov=pfsense_cli --cov-report=html --cov-report=term

test-unit:
	pytest -v -m "unit" --cov=pfsense_cli

test-integration:
	pytest -v -m "integration"

test-quick:
	pytest -v -x --ff

# Code quality commands
lint:
	flake8 pfsense_cli/ tests/
	mypy pfsense_cli/

format:
	black pfsense_cli/ tests/
	isort pfsense_cli/ tests/

type-check:
	mypy pfsense_cli/

# Cleanup commands
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build commands
build: clean
	python -m build

# Documentation commands
docs:
	mkdocs build

docs-serve:
	mkdocs serve

# Docker commands
docker:
	docker build -t pfsense-cli .

# Example usage commands
example: install
	@echo "Running example commands..."
	@echo "1. Show help"
	pfsense-cli --help
	@echo "\n2. Check status (will fail without setup)"
	-pfsense-cli status
	@echo "\n3. List available templates"
	@echo "   (Templates will be created on first run)"

# Development workflow
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to check code quality"
	@echo "Run 'make format' to format code"

# CI/CD commands
ci: lint test
	@echo "CI checks passed!"

# Release commands
check-release:
	python -m twine check dist/*

upload-test:
	python -m twine upload --repository testpypi dist/*

upload-prod:
	python -m twine upload dist/*

# Quick development cycle
dev: format lint test
	@echo "Development cycle complete!"

# Show project structure
tree:
	tree -I '__pycache__|*.pyc|.git|.pytest_cache|htmlcov|.mypy_cache|*.egg-info|build|dist'