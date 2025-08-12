.PHONY: setup run test clean

setup:
	python -m venv .venv
	# Windows PowerShell: . .\.venv\Scripts\Activate.ps1
	# macOS/Linux: source .venv/bin/activate
	pip install -r requirements.txt
	pip install pytest

run:
	python detect.py

test:
	pytest -q

clean:
	rm -rf .venv __pycache__ .pytest_cache alerts.csv