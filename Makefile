# Makefile for SSH Brute Force Detection Tool

.PHONY: help install test lint format clean run-sample

# Default target
help:
	@echo "SSH Brute Force Detection Tool - Available Commands:"
	@echo ""
	@echo "  install      Install the tool and dependencies"
	@echo "  test         Run the test suite"
	@echo "  lint         Run code linting (flake8)"
	@echo "  format       Format code with Black"
	@echo "  type-check   Run type checking with mypy"
	@echo "  run-sample   Run the tool with sample data"
	@echo "  clean        Clean up temporary files"
	@echo ""

# Install the tool and dependencies
install:
	@echo "Installing SSH Brute Force Detection Tool..."
	pip install -r requirements.txt
	chmod +x bruteforce_detector.py
	chmod +x test_bruteforce_detector.py

# Run the test suite
test:
	@echo "Running test suite..."
	python3 test_bruteforce_detector.py

# Run linting
lint:
	@echo "Running flake8 linting..."
	flake8 bruteforce_detector.py --max-line-length=88 --extend-ignore=E203,W503

# Format code
format:
	@echo "Formatting code with Black..."
	black bruteforce_detector.py test_bruteforce_detector.py

# Type checking
type-check:
	@echo "Running mypy type checking..."
	mypy bruteforce_detector.py --ignore-missing-imports

# Run with sample data
run-sample:
	@echo "Running with sample auth.log data..."
	python3 bruteforce_detector.py -f sample_auth.log -t 3 -w 60

# Clean up temporary files
clean:
	@echo "Cleaning up temporary files..."
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.csv" -delete
	find . -name "*.json" -delete
	find . -name ".mypy_cache" -type d -exec rm -rf {} +
	find . -name ".pytest_cache" -type d -exec rm -rf {} +

# Development setup
dev-install:
	@echo "Setting up development environment..."
	python3 -m venv venv
	. venv/bin/activate && pip install -r requirements.txt
	@echo "Activate virtual environment with: source venv/bin/activate"

# Package the tool
package:
	@echo "Creating package..."
	python3 setup.py sdist bdist_wheel

# Quality check (lint + type-check + test)
quality:
	@echo "Running full quality check..."
	make lint
	make type-check
	make test
	@echo "✅ Quality check completed!"
