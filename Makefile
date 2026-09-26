.PHONY: check lint test build docs

check: lint test docs

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run bandit -r src/
	uv run mypy
	uvx ty check src tests

test:
	uv run pytest --cov --cov-report=term-missing

docs:
	uv run --group docs mkdocs build --strict

build:
	uv build
