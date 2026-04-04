.PHONY: test lint format demo install install-memory install-all bench

install:
	pip install -e ".[dev]"

install-memory:
	pip install -e ".[memory,dev]"

install-all:
	pip install -e ".[all,dev,bench]"

test:
	pytest tests/ -v --cov=src/agent_immune --cov-report=term-missing

lint:
	ruff check src/ tests/ demos/ bench/
	ruff format --check src/ tests/ demos/ bench/

format:
	ruff format src/ tests/ demos/ bench/

demo:
	python demos/demo_standalone.py

demo-semantic:
	python demos/demo_semantic_catch.py

demo-escalation:
	python demos/demo_escalation.py

bench:
	python bench/run_benchmarks.py
