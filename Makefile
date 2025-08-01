# Format the code using Black and Ruff's formatter
format:
	# Format all Python files with Black (opinionated code formatter)
	poetry run black . --verbose
	# Format with Ruff (fast, also ensures consistency; runs import sorting if enabled)
	poetry run ruff format . --verbose

# Lint the code using Ruff (includes rules from flake8, isort, etc.)
lint:
	# Perform static linting with Ruff; checks for style issues and common errors
	poetry run ruff check . --verbose

# Type-check the code using MyPy
typecheck:
	# Run MyPy with verbose output to check for type errors
	poetry run mypy . --verbose


all: format lint typecheck
	# Run all tasks: format, lint, and type-check