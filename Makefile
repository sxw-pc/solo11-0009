.PHONY: install test demo fixture audit clean linkdemo

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -q

demo:
	python -m maskline demo

linkdemo:
	python -m maskline linkdemo

fixture:
	python scripts/make_fixture.py

audit:
	python -m maskline audit --verify

clean:
	rm -rf data reports audit .pytest_cache .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
