# Windows Event Log — Mini Detection Lab

Parses Windows Security logs from CSV and raises alerts for:
- **Failed-logon surges** (Event ID `4625`)
- **Suspicious process creation** (Event ID `4688`, e.g., encoded PowerShell, certutil)

This is a small, reproducible demo that highlights Python scripting, basic detection logic, and clean repo hygiene.

## Quick Start
```bash
# Create & activate a venv
python -m venv .venv
# Windows PowerShell:
. .\.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt

# Run on the included sample data
python detect.py

# Outputs alerts to alerts.csv and prints a short summary