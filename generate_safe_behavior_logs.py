"""
generate_safe_behavior_logs.py
================================
Sinh log hành vi giả lập THỰC TẾ HƠN dựa trên:
- Hành vi benign: chrome, vscode, python, office, backup tools
- Hành vi ransomware: mô phỏng LockBit 3.0 (CISA advisory + MITRE S1202)
  Phase 1: Reconnaissance (đọc file)
  Phase 2: Mass encryption (ghi file entropy cao + rename)
  Phase 3: Defense evasion (xóa shadow copy, dừng service, sửa registry)
  Phase 4: C2 communication (DNS, network)

Output: data/raw/behavior_logs/simulated_behavior.csv
"""

import random
import os
import pandas as pd
from datetime import datetime, timedelta

random.seed(42)

OUTPUT_DIR = "data/raw/behavior_logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "simulated_behavior.csv")
os.makedirs(OUTPUT_DIR, exist_ok=True)

events = []
event_id = 0
base_time = datetime(2024, 6, 1, 8, 0, 0)

EXTENSIONS = [".docx", ".xlsx", ".pdf", ".jpg", ".png", ".txt", ".csv", ".pptx", ".zip", ".db"]
LOCKBIT_EXT = ".lockbit"

BENIGN_PROCESSES = [
    ("chrome.exe",      1100, "explorer.exe"),
    ("code.exe",        1200, "explorer.exe"),
    ("python.exe",      1300, "cmd.exe"),
    ("WINWORD.EXE",     1400, "explorer.exe"),
    ("EXCEL.EXE",       1500, "explorer.exe"),
    ("OneDrive.exe",    1600, "explorer.exe"),
    ("SearchIndexer",   1700, "services.exe"),
    ("MsMpEng.exe",     1800, "services.exe"),
]

BENIGN_DOMAINS = [
    "update.microsoft.com", "github.com", "pypi.org",
    "office.com", "onedrive.live.com", "google.com",
]

SUSPICIOUS_DOMAINS = [
    "random-check.onion.link", "lockbit-cdn.example",
    "update-node.xyz", "sync-api.ru", "cdn-deliver.onion",
]

BACKUP_SERVICES = ["VSS", "wbengine", "SDRSVC", "swprv"]
SECURITY_SERVICES = ["MsMpSvc", "WinDefend", "wscsvc", "SecurityHealthService"]
DB_SERVICES = ["MSSQLSERVER", "MySQL80", "postgresql-x64-14"]


def add_event(ts, process, pid, parent, event_type, operation, obj,
              label, family="benign",
              bytes_written=0, entropy_before=0.0, entropy_after=0.0,
              dst_ip="", dst_port=0, domain="", extension=""):
    global event_id
    events.append({
        "event_index":    event_id,
        "timestamp":      ts.isoformat(),
        "source_type":    "simulated_behavior",
        "host_id":        "WIN11-LAB-01",
        "process_name":   process,
        "pid":            pid,
        "parent_process": parent,
        "event_type":     event_type,
        "operation":      operation,
        "object":         obj,
        "extension":      extension,
        "bytes_written":  bytes_written,
        "entropy_before": entropy_before,
        "entropy_after":  entropy_after,
        "dst_ip":         dst_ip,
        "dst_port":       dst_port,
        "domain":         domain,
        "label":          label,
        "family":         family,
    })
    event_id += 1


# ============================================================
# PHASE BENIGN — 2000 events, ~30 menit aktivitas normal
# ============================================================
print("[*] Generating benign events...")
for i in range(2000):
    ts = base_time + timedelta(seconds=i * 0.9)
    proc, pid, parent = random.choice(BENIGN_PROCESSES)
    r = random.random()
    ext = random.choice(EXTENSIONS)
    doc_id = random.randint(1, 300)
    fpath = f"C:\\Users\\victim\\Documents\\file_{doc_id}{ext}"

    if r < 0.40:
        add_event(ts, proc, pid, parent, "file_read", "read", fpath,
                  "benign", extension=ext)
    elif r < 0.60:
        add_event(ts, proc, pid, parent, "file_write", "write", fpath,
                  "benign", extension=ext,
                  bytes_written=random.randint(100, 8000),
                  entropy_before=round(random.uniform(3.0, 5.5), 3),
                  entropy_after=round(random.uniform(3.0, 5.8), 3))
    elif r < 0.70:
        add_event(ts, proc, pid, parent, "process_create", "exec", proc, "benign")
    elif r < 0.82:
        domain = random.choice(BENIGN_DOMAINS)
        add_event(ts, proc, pid, parent, "dns_query", "query", domain,
                  "benign", domain=domain)
    elif r < 0.92:
        add_event(ts, proc, pid, parent, "network_connect", "connect", "remote",
                  "benign",
                  dst_ip=f"20.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                  dst_port=random.choice([80, 443]))
    else:
        rkey = random.choice([
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        ])
        add_event(ts, proc, pid, parent, "registry_set", "set", rkey, "benign")


# ============================================================
# PHASE RANSOMWARE — LockBit 3.0 simulation
# ============================================================
print("[*] Generating ransomware (LockBit 3.0 simulation) events...")

RANSOM_PROC = "svchost_upd.exe"   # masquerading
RANSOM_PID  = 9999
RANSOM_PAR  = "cmd.exe"
BASE_RANSOM = base_time + timedelta(seconds=2000 * 0.9)

# --- Sub-phase 1: Reconnaissance (100 events) ---
for i in range(100):
    ts = BASE_RANSOM + timedelta(seconds=i * 0.1)
    ext = random.choice(EXTENSIONS)
    fpath = f"C:\\Users\\victim\\Documents\\file_{random.randint(1,300)}{ext}"
    add_event(ts, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "file_read", "read", fpath, "ransomware", "LockBit3",
              extension=ext,
              entropy_before=round(random.uniform(3.0, 5.5), 3),
              entropy_after=round(random.uniform(3.0, 5.5), 3))

# --- Sub-phase 2: Mass encryption (800 events) ---
print("   [*] Encryption phase...")
for i in range(800):
    ts = BASE_RANSOM + timedelta(seconds=10 + i * 0.08)
    doc_id = random.randint(1, 400)
    ext = random.choice(EXTENSIONS)
    orig = f"C:\\Users\\victim\\Documents\\file_{doc_id}{ext}"

    if random.random() < 0.65:
        # Ghi đè file gốc với nội dung mã hóa (entropy cao)
        add_event(ts, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
                  "file_write", "write", orig, "ransomware", "LockBit3",
                  extension=ext,
                  bytes_written=random.randint(10000, 100000),
                  entropy_before=round(random.uniform(3.0, 5.5), 3),
                  entropy_after=round(random.uniform(7.2, 7.99), 3))
    else:
        # Rename sang .lockbit
        new_path = orig + LOCKBIT_EXT
        add_event(ts, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
                  "file_rename", "rename", new_path, "ransomware", "LockBit3",
                  extension=LOCKBIT_EXT,
                  bytes_written=0,
                  entropy_before=round(random.uniform(7.0, 7.99), 3),
                  entropy_after=round(random.uniform(7.0, 7.99), 3))

# --- Sub-phase 3: Defense evasion (T1490, T1489, T1112) ---
ts_def = BASE_RANSOM + timedelta(seconds=10 + 800 * 0.08)

# Xóa shadow copy (T1490)
for svc in BACKUP_SERVICES:
    add_event(ts_def, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "shadow_copy_delete", "delete", f"shadow_copy_{svc}",
              "ransomware", "LockBit3")
    ts_def += timedelta(seconds=0.5)

# Dừng service (T1489)
for svc in BACKUP_SERVICES + SECURITY_SERVICES + DB_SERVICES:
    add_event(ts_def, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "service_stop", "stop", svc, "ransomware", "LockBit3")
    ts_def += timedelta(seconds=0.3)

# Sửa Registry (T1112) — disable recovery
reg_keys = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\CryptoSvc",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\LockBit",
]
for key in reg_keys:
    add_event(ts_def, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "registry_set", "set", key, "ransomware", "LockBit3")
    ts_def += timedelta(seconds=0.2)

# --- Sub-phase 4: C2 Communication (T1071) ---
for i in range(50):
    ts_def += timedelta(seconds=0.5)
    domain = random.choice(SUSPICIOUS_DOMAINS)
    add_event(ts_def, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "dns_query", "query", domain, "ransomware", "LockBit3",
              domain=domain)
    add_event(ts_def, RANSOM_PROC, RANSOM_PID, RANSOM_PAR,
              "network_connect", "connect", "remote", "ransomware", "LockBit3",
              dst_ip=f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
              dst_port=random.choice([443, 80, 8443]))


# ============================================================
# Save
# ============================================================
df = pd.DataFrame(events)
df.to_csv(OUTPUT_FILE, index=False)

print(f"\n[+] Saved: {OUTPUT_FILE}")
print(f"    Total events : {len(df):,}")
print(f"    Benign       : {(df['label']=='benign').sum():,}")
print(f"    Ransomware   : {(df['label']=='ransomware').sum():,}")
print(f"\n    Event types:")
print(df["event_type"].value_counts().to_string())
