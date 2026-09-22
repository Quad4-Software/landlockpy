.PHONY: check lint test build

check: lint test

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run bandit -r src/
	uv run mypy

test:
	uv run pytest

build:
	uv build
