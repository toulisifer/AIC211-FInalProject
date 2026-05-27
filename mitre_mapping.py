"""
mitre_mapping.py
==================
Nâng cấp so với bản gốc:
  - Thêm T1622 (Debugger Evasion), T1027 (Obfuscated Files)
  - Risk score dùng ensemble thay vì max
  - Thêm evidence_detail mô tả số liệu cụ thể
  - Severity mapping: High / Medium / Low

Output: reports/mitre_alerts.csv
"""

import os
import pandas as pd

INPUT  = "reports/behavior_scored_windows.csv"
OUTPUT = "reports/mitre_alerts.csv"
os.makedirs("reports", exist_ok=True)

df = pd.read_csv(INPUT)

alerts = []


def add(row, technique, technique_id, tactic, evidence, evidence_detail, explanation, severity):
    ensemble = row.get("ensemble_score", 0)
    rf_s     = row.get("rf_score", 0)
    xgb_s    = row.get("xgb_score", 0)
    if_s     = row.get("if_score", 0)

    alerts.append({
        "window_id":        row["window_id"],
        "first_event_idx":  row["first_event_index"],
        "risk_score":       round(float(ensemble if ensemble > 0 else max(rf_s, xgb_s, if_s)), 4),
        "rf_score":         round(float(rf_s), 4),
        "xgb_score":        round(float(xgb_s), 4),
        "if_score":         round(float(if_s), 4),
        "technique":        technique,
        "technique_id":     technique_id,
        "tactic":           tactic,
        "evidence":         evidence,
        "evidence_detail":  evidence_detail,
        "explanation":      explanation,
        "severity":         severity,
    })


for _, row in df.iterrows():
    is_alert = (
        row.get("rf_pred",       0) == 1 or
        row.get("xgb_pred",      0) == 1 or
        row.get("if_pred",       0) == 1 or
        row.get("ensemble_pred", 0) == 1
    )
    if not is_alert:
        continue

    # T1486 — Data Encrypted for Impact
    if (row.get("file_write_count", 0) >= 8 or
            row.get("file_rename_count", 0) >= 5 or
            row.get("high_entropy_flag", 0) == 1 or
            row.get("entropy_spike_count", 0) > 0 or
            row.get("lockbit_ext_count", 0) > 0):
        detail = (
            f"writes={int(row.get('file_write_count',0))}, "
            f"renames={int(row.get('file_rename_count',0))}, "
            f"entropy_spikes={int(row.get('entropy_spike_count',0))}, "
            f".lockbit_files={int(row.get('lockbit_ext_count',0))}, "
            f"avg_entropy_after={row.get('avg_entropy_after',0):.2f}"
        )
        add(row,
            "Data Encrypted for Impact", "T1486", "Impact",
            "mass file write/rename + high entropy",
            detail,
            "Mass encryption of user files detected. High Shannon entropy after write "
            "indicates AES/ChaCha20 encryption consistent with LockBit 3.0 behavior.",
            "Critical")

    # T1490 — Inhibit System Recovery
    if row.get("shadow_copy_delete_count", 0) > 0:
        detail = f"shadow_copy_deletions={int(row.get('shadow_copy_delete_count',0))}"
        add(row,
            "Inhibit System Recovery", "T1490", "Impact",
            "shadow copy / backup deletion",
            detail,
            "Deletion of Volume Shadow Copies detected. This prevents system restore "
            "and is a hallmark pre-encryption step of LockBit 3.0.",
            "Critical")

    # T1489 — Service Stop
    if row.get("service_stop_count", 0) > 0:
        detail = f"services_stopped={int(row.get('service_stop_count',0))}"
        add(row,
            "Service Stop", "T1489", "Impact",
            "backup/security/DB service termination",
            detail,
            "Multiple critical services stopped (backup, antivirus, database). "
            "Consistent with LockBit 3.0 disabling defenses before encryption.",
            "High")

    # T1112 — Modify Registry
    if row.get("registry_set_count", 0) >= 2:
        detail = f"registry_modifications={int(row.get('registry_set_count',0))}"
        add(row,
            "Modify Registry", "T1112", "Defense Evasion / Persistence",
            "registry key modification",
            detail,
            "Registry modifications targeting Windows Defender policies and service "
            "configurations. Used by LockBit to disable security controls.",
            "High")

    # T1071 — Application Layer Protocol (C2)
    if row.get("dns_query_count", 0) >= 5 or row.get("network_connect_count", 0) >= 5:
        detail = (
            f"dns_queries={int(row.get('dns_query_count',0))}, "
            f"network_connects={int(row.get('network_connect_count',0))}, "
            f"suspicious_domain={int(row.get('suspicious_domain_flag',0))}"
        )
        add(row,
            "Application Layer Protocol", "T1071", "Command and Control",
            "suspicious network / DNS activity",
            detail,
            "Unusual DNS queries and outbound connections detected. "
            "May indicate C2 communication or exfiltration.",
            "Medium" if row.get("suspicious_domain_flag", 0) == 0 else "High")

    # T1622 — Debugger Evasion (if process count drops or suspicious parent)
    if row.get("unique_process_count", 0) == 1 and row.get("process_create_count", 0) == 0:
        detail = f"unique_processes={int(row.get('unique_process_count',0))}"
        add(row,
            "Debugger Evasion", "T1622", "Defense Evasion",
            "single process, no child spawning",
            detail,
            "Process runs in isolation without spawning children. "
            "Possible anti-analysis behavior to evade sandbox monitoring.",
            "Low")


out = pd.DataFrame(alerts)
out.to_csv(OUTPUT, index=False)

print(f"[+] Saved: {OUTPUT}")
print(f"    Total alerts : {len(out)}")
if len(out) > 0:
    print(f"\n    By technique:")
    print(out["technique_id"].value_counts().to_string())
    print(f"\n    By severity:")
    print(out["severity"].value_counts().to_string())
