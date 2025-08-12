import pandas as pd
from pathlib import Path
from detectors import failed_logon_surge, suspicious_process_creation

def load_sample():
    p = Path("sample_data") / "events.csv"
    df = pd.read_csv(p)
    df["EventID"] = pd.to_numeric(df["Id"])
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True)
    df["Message"] = df["Message"].astype(str)
    return df

def test_failed_logon_surge_triggers_on_sample():
    df = load_sample()
    alerts = failed_logon_surge(df, window="2min", threshold=3)
    assert len(alerts) >= 1

def test_suspicious_process_detects_encoded_ps():
    df = load_sample()
    alerts = suspicious_process_creation(df)
    assert any(a.get("indicator") for a in alerts)