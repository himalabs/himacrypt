######################
# Makefile shortcuts
######################

POETRY := poetry
PYTEST_ARGS := tests --verbose

.DEFAULT_GOAL := help

.PHONY: help format lint lint-fix typecheck test all install clean

help:
	@echo "Makefile tasks:"
	@echo "  make format      - Format code with black and ruff"
	@echo "  make lint        - Run ruff linter"
	@echo "  make lint-fix    - Run ruff auto-fixes (and format)"
	@echo "  make typecheck   - Run mypy type checks"
	@echo "  make test        - Run pytest on the tests directory"
	@echo "  make all         - format, lint, typecheck and test"
	@echo "  make install     - Install project dependencies via poetry"
	@echo "  make clean       - Remove Python cache files"

# Format the code using Black and Ruff's formatter
format:
	# Format all Python files with Black (opinionated code formatter)
	$(POETRY) run black . --verbose
	# Format with Ruff (fast, also ensures consistency; runs import sorting if enabled)
	$(POETRY) run ruff format . --verbose

# Lint the code using Ruff (includes rules from flake8, isort, etc.)
lint:
	# Perform static linting with Ruff; checks for style issues and common errors
	$(POETRY) run ruff check . --verbose

# Attempt to auto-fix lint issues where possible
lint-fix:
	# Ruff can attempt fixes; run format afterwards to ensure black/ruff format is applied
	$(POETRY) run ruff check --fix . --verbose || true
	$(POETRY) run ruff format . --verbose || true
	$(POETRY) run black . --verbose || true

# Type-check the code using MyPy
typecheck:
	# Run MyPy with verbose output to check for type errors
	$(POETRY) run mypy . --verbose

# Run the tests
test:
	$(POETRY) run pytest $(PYTEST_ARGS)

install:
	$(POETRY) install

clean:
	@echo "Cleaning up Python cache files..."
	@find . -name '__pycache__' -type d -exec rm -rf {} + || true
	@find . -name '*.pyc' -delete || true

all: format lint typecheck test
	@echo "All checks completed."
