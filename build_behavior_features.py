"""
build_behavior_features.py
============================
Đọc simulated_behavior.csv, chia thành window 50 events,
trích xuất đặc trưng hành vi đầy đủ hơn bản gốc:

Đặc trưng bổ sung so với bản gốc:
  - rename_to_write_ratio
  - lockbit_ext_count       (đếm file đổi sang .lockbit)
  - entropy_spike_count     (entropy_after > 7.0)
  - suspicious_domain_flag
  - defense_evasion_score   (tổng shadow + service stop + registry)
  - process_injection_flag  (parent mismatch pattern)

Output: data/processed/behavior/behavior_features.csv
"""

import os
import pandas as pd
import numpy as np

INPUT  = "data/raw/behavior_logs/simulated_behavior.csv"
OUTPUT_DIR = "data/processed/behavior"
OUTPUT = os.path.join(OUTPUT_DIR, "behavior_features.csv")
os.makedirs(OUTPUT_DIR, exist_ok=True)

WINDOW_SIZE = 50

SUSPICIOUS_DOMAINS = {
    "random-check.onion.link", "lockbit-cdn.example",
    "update-node.xyz", "sync-api.ru", "cdn-deliver.onion",
}

print(f"[*] Reading {INPUT} ...")
df = pd.read_csv(INPUT)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("event_index").reset_index(drop=True)
df["window_id"] = df["event_index"] // WINDOW_SIZE

print(f"[+] {len(df):,} events → {df['window_id'].nunique()} windows (size={WINDOW_SIZE})")

rows = []

for window_id, g in df.groupby("window_id"):

    # --- Basic counts ---
    row = {
        "window_id":               int(window_id),
        "first_event_index":       int(g["event_index"].min()),
        "last_event_index":        int(g["event_index"].max()),
        "event_count":             len(g),

        # File ops
        "file_read_count":         int((g["event_type"] == "file_read").sum()),
        "file_write_count":        int((g["event_type"] == "file_write").sum()),
        "file_rename_count":       int((g["event_type"] == "file_rename").sum()),
        "file_delete_count":       int((g["event_type"] == "file_delete").sum()),

        # Defense evasion
        "shadow_copy_delete_count": int((g["event_type"] == "shadow_copy_delete").sum()),
        "service_stop_count":       int((g["event_type"] == "service_stop").sum()),
        "registry_set_count":       int((g["event_type"] == "registry_set").sum()),

        # Network / Process
        "dns_query_count":          int((g["event_type"] == "dns_query").sum()),
        "network_connect_count":    int((g["event_type"] == "network_connect").sum()),
        "process_create_count":     int((g["event_type"] == "process_create").sum()),

        # Object diversity
        "unique_object_count":      int(g["object"].nunique()),
        "unique_process_count":     int(g["process_name"].nunique()),
        "unique_extension_count":   int(g["extension"].dropna().nunique()) if "extension" in g.columns else 0,

        # Bytes & Entropy
        "total_bytes_written":      int(g["bytes_written"].fillna(0).sum()),
        "avg_entropy_before":       float(g["entropy_before"].fillna(0).mean()),
        "avg_entropy_after":        float(g["entropy_after"].fillna(0).mean()),
        "entropy_delta":            float(
            (g["entropy_after"].fillna(0) - g["entropy_before"].fillna(0)).clip(lower=0).mean()
        ),
        "max_entropy_after":        float(g["entropy_after"].fillna(0).max()),

        # Labels
        "label":  "ransomware" if (g["label"] == "ransomware").any() else "benign",
        "family": g["family"].mode()[0] if len(g) > 0 else "benign",
    }

    # --- Derived features ---
    total_file = max(row["file_read_count"] + row["file_write_count"] + row["file_rename_count"], 1)

    row["rename_burst_score"]    = row["file_rename_count"] / total_file
    row["write_burst_score"]     = row["file_write_count"]  / max(row["event_count"], 1)
    row["rename_to_write_ratio"] = row["file_rename_count"] / max(row["file_write_count"], 1)

    # Entropy spikes: số file bị ghi với entropy_after > 7.0
    writes = g[g["event_type"] == "file_write"]
    row["entropy_spike_count"] = int((writes["entropy_after"].fillna(0) > 7.0).sum())
    row["high_entropy_flag"]   = 1 if row["entropy_delta"] > 2.0 or row["entropy_spike_count"] > 0 else 0

    # LockBit extension
    if "extension" in g.columns:
        row["lockbit_ext_count"] = int((g["extension"] == ".lockbit").sum())
    else:
        row["lockbit_ext_count"] = 0

    # Suspicious domain
    if "domain" in g.columns:
        row["suspicious_domain_flag"] = int(
            g["domain"].dropna().apply(lambda d: d in SUSPICIOUS_DOMAINS).any()
        )
    else:
        row["suspicious_domain_flag"] = 0

    # Defense evasion composite score
    row["defense_evasion_score"] = (
        row["shadow_copy_delete_count"] * 3 +
        row["service_stop_count"] * 2 +
        row["registry_set_count"] * 1
    )

    # Affected file events (ghi + rename + xóa)
    row["affected_file_events"] = (
        row["file_write_count"] + row["file_rename_count"] + row["file_delete_count"]
    )

    rows.append(row)

features = pd.DataFrame(rows)

# Sanity check
print(f"\n[+] Feature matrix shape: {features.shape}")
print(f"    Ransomware windows : {(features['label']=='ransomware').sum()}")
print(f"    Benign windows     : {(features['label']=='benign').sum()}")
print(f"\n    Feature columns: {list(features.columns)}")

features.to_csv(OUTPUT, index=False)
print(f"\n[+] Saved: {OUTPUT}")
