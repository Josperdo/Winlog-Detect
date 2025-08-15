# Windows Event Log — Mini Detection Lab

Parses Windows Security logs from CSV and raises alerts for:
- **Failed-logon surges** (Event ID `4625`)
- **Suspicious process creation** (Event ID `4688`, e.g., encoded PowerShell, certutil)

This is a small, reproducible demo that highlights Python scripting, basic detection logic, and clean repo hygiene.

## Quick Start
1. Clone the repo
```bash
git clone https://github.com/Josperdo/winlog-detect.git
cd winlog-detect
```

2. Create and activate a virtual environment

  Windows PowerShell
```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
```
  macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Run the detection script
```python
python detect.py
```
By default, it uses the sample CSV in sample_data/events.csv and writes alerts to alerts.csv.



## Project Structure
```bash
winlog-detect/
├── detect.py                 # Main entry point
├── detectors.py              # Detection functions
├── sample_data/events.csv    # Sample log data
├── scripts/export_events.ps1 # Windows log export helper
├── tests/                    # Basic unit tests
├── requirements.txt          # Python dependencies
├── Makefile                  # Convenience commands
├── .github/workflows/ci.yml  # CI test workflow
└── README.md
```

## Exporting Your Own Logs (Optional)
If running on Windows and you want real logs:
```powershell
cd scripts
.\export_events.ps1
cd ..
python detect.py --input sample_data\events.csv
```
**Tip**: Run PowerShell as Administrator.
If you get a script execution policy error, run:
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```
## Detection Logic ##

**Failed-Logon Surge (4625)**

- Groups logs in time windows (default 2min)
- Alerts if failed logon count exceeds threshold (default 3)

**Suspicious Process Creation (4688)**

- Looks for suspicious command-line tokens such as:
  - -enc
  - certutil
  - mshta
  - rundll32
  - wmic
  - and others

## Tech Used ##

- Python — pandas for CSV parsing and analysis
- PowerShell — log export script
- GitHub Actions — CI pipeline for running tests

## Licnense ##

This project is released under the MIT License.
It is intended for educational and defensive purposes only.
