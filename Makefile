.PHONY: help install lint format typecheck pylint test coverage build docs docs-serve clean

PYTHON ?= python3
VENV ?= .venv
ACTIVATE := . $(VENV)/bin/activate &&

help:
	@echo "HydraSight developer targets:"
	@echo "  install    create venv and install with dev+docs extras"
	@echo "  lint       ruff lint + format check"
	@echo "  format     apply ruff format"
	@echo "  typecheck  mypy"
	@echo "  pylint     pylint with score floor"
	@echo "  test       pytest (no ethereum plugin)"
	@echo "  coverage   pytest with branch coverage (floor 75%)"
	@echo "  build      python -m build (sdist + wheel)"
	@echo "  docs       mkdocs build --strict"
	@echo "  docs-serve live-reload docs server"
	@echo "  clean      remove build artifacts"

install:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) pip install -e ".[dev,docs]"

lint:
	$(ACTIVATE) ruff check hydrasight/ tests/
	$(ACTIVATE) ruff format --check hydrasight/ tests/

format:
	$(ACTIVATE) ruff format hydrasight/ tests/

typecheck:
	$(ACTIVATE) mypy hydrasight/ --ignore-missing-imports

pylint:
	$(ACTIVATE) pylint hydrasight/ --fail-under=9.0

test:
	$(ACTIVATE) pytest tests/ -p no:ethereum -q

coverage:
	$(ACTIVATE) pytest tests/ -p no:ethereum --cov=hydrasight --cov-branch \
		--cov-report=term-missing --cov-fail-under=75 -q

build:
	$(ACTIVATE) $(PYTHON) -m build

docs:
	$(ACTIVATE) mkdocs build --strict

docs-serve:
	$(ACTIVATE) mkdocs serve

clean:
	rm -rf build dist *.egg-info site .pytest_cache .mypy_cache .ruff_cache htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
