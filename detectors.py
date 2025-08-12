import pandas as pd

SUSPICIOUS_TOKENS = [
    "-enc", "encodedcommand", "certutil", "rundll32", "mshta",
    "bitsadmin", "wmic", "wscript", "cscript", "regsvr32"
]

def failed_logon_surge(df: pd.DataFrame, window: str = "2min", threshold: int = 3):
    sec = df[df["EventID"] == 4625].copy()
    if sec.empty:
        return []
    sec = sec.set_index("TimeCreated").sort_index()
    counts = sec["EventID"].resample(window).count()
    hits = counts[counts >= threshold]
    alerts = []
    for ts, cnt in hits.items():
        alerts.append({
            "rule": "failed_logon_surge",
            "time_utc": ts.isoformat(),
            "count": int(cnt),
            "window": window
        })
    return alerts

def suspicious_process_creation(df: pd.DataFrame):
    proc = df[df["EventID"] == 4688].copy()
    if proc.empty:
        return []
    alerts = []
    for _, row in proc.iterrows():
        msg = str(row.get("Message", "")).lower()
        if any(tok in msg for tok in SUSPICIOUS_TOKENS):
            alerts.append({
                "rule": "suspicious_process_creation",
                "time_utc": row["TimeCreated"].isoformat() if pd.notna(row["TimeCreated"]) else "",
                "indicator": next(tok for tok in SUSPICIOUS_TOKENS if tok in msg),
            })
    return alerts