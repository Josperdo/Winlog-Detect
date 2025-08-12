import argparse
import pandas as pd
from pathlib import Path
from detectors import failed_logon_surge, suspicious_process_creation

def load_events(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    rename_map = {
        "Id": "EventID",
        "TimeCreated": "TimeCreated",
        "Message": "Message",
        "ProviderName": "ProviderName",
        "LevelDisplayName": "Level",
    }
    cols = [c for c in rename_map.keys() if c in df.columns]
    df = df[cols].rename(columns=rename_map)
    df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce")
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce", utc=True)
    df["Message"] = df["Message"].astype(str)
    return df.dropna(subset=["EventID", "TimeCreated"])

def main():
    parser = argparse.ArgumentParser(description="Windows log mini detection")
    parser.add_argument("--input", default=str(Path("sample_data") / "events.csv"))
    parser.add_argument("--out", default="alerts.csv")
    parser.add_argument("--failed-window", default="2min")
    parser.add_argument("--failed-threshold", type=int, default=3)
    args = parser.parse_args()

    df = load_events(Path(args.input))

    alerts = []
    alerts += failed_logon_surge(df, window=args.failed_window, threshold=args.failed_threshold)
    alerts += suspicious_process_creation(df)

    if alerts:
        out_df = pd.DataFrame(alerts)
        out_df.to_csv(args.out, index=False)
        print(f"[+] {len(alerts)} alerts written to {args.out}")
        by_rule = out_df.groupby("rule").size().to_dict()
        print("[+] Summary:", by_rule)
    else:
        print("[+] No alerts generated.")

if __name__ == "__main__":
    main()