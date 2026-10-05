"""Generate data/sample_logs.csv — realistic benign telemetry with ONE unlabeled attack.

Benign: 12 hosts, normal process/network/logon activity over ~8h.
Attack (NOT labeled anywhere in the CSV):
  - ws-107 -> 45.148.10.88 : 12 egress connections at exactly 60s intervals
  - 4624 Type 3: ws-107 -> ws-109, ws-109 -> srv-file01 (workstation hops)
  - admin share C$ on ws-109 -> srv-file01
  - onward Type 3 hop toward dc01
Detectors must find all of this from timing/structure math alone.
"""
import csv
import random
from datetime import datetime, timezone, timedelta

random.seed(20261005)
BASE = datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


workstations = [f"ws-10{i}" for i in range(1, 11)]
servers = ["srv-file01", "srv-db01"]
users = ["a.sharma", "r.verma", "s.patil", "k.iyer", "m.das", "p.nair"]
benign_ips = ["142.250.195.14", "13.107.42.14", "52.96.164.2", "20.190.159.2"]
procs = ["chrome.exe", "outlook.exe", "teams.exe", "explorer.exe", "svchost.exe"]

rows = []

# benign process creations (Sysmon 1)
for _ in range(60):
    h = random.choice(workstations)
    dt = BASE + timedelta(seconds=random.randint(0, 8 * 3600))
    rows.append({
        "timestamp": ts(dt), "event_id": "1", "computer": h,
        "user": random.choice(users), "image": random.choice(procs),
    })

# benign network (Sysmon 3) — irregular human timing
for _ in range(70):
    h = random.choice(workstations + servers)
    dt = BASE + timedelta(seconds=random.randint(0, 8 * 3600),
                          milliseconds=random.randint(0, 999))
    rows.append({
        "timestamp": ts(dt), "event_id": "3", "computer": h,
        "dst_ip": random.choice(benign_ips),
        "user": random.choice(users), "image": random.choice(procs),
        "destination_port": "443",
    })

# benign logons (4624) — Type 2/11 interactive
for _ in range(50):
    h = random.choice(workstations)
    dt = BASE + timedelta(seconds=random.randint(0, 8 * 3600))
    rows.append({
        "timestamp": ts(dt), "event_id": "4624", "computer": h,
        "src_host": h, "user": random.choice(users),
        "logon_type": str(random.choice([2, 11])),
    })

# benign server access (workstation -> server is normal admin/user traffic)
for _ in range(12):
    s, d = random.choice(workstations), random.choice(servers)
    dt = BASE + timedelta(seconds=random.randint(0, 8 * 3600))
    rows.append({
        "timestamp": ts(dt), "event_id": "4624", "computer": d,
        "src_host": s, "user": random.choice(users), "logon_type": "3",
    })

# ---- attack: periodic egress beacon (unlabeled) ----
t0 = BASE + timedelta(hours=3, minutes=17)
for k in range(12):
    dt = t0 + timedelta(seconds=60 * k)  # exact 60s period
    rows.append({
        "timestamp": ts(dt), "event_id": "3", "computer": "ws-107",
        "dst_ip": "45.148.10.88", "user": "a.sharma",
        "image": "svchost.exe", "destination_port": "443",
    })

# ---- attack: lateral movement via Type 3 workstation hops (unlabeled) ----
t1 = t0 + timedelta(minutes=14)
rows.append({
    "timestamp": ts(t1), "event_id": "4624", "computer": "ws-109",
    "src_host": "ws-107", "user": "a.sharma", "logon_type": "3",
})
t2 = t1 + timedelta(minutes=6)
rows.append({
    "timestamp": ts(t2), "event_id": "4624", "computer": "srv-file01",
    "src_host": "ws-109", "user": "a.sharma", "logon_type": "3",
    "share": "C$",
})
# ---- attack: onward toward the domain controller (unlabeled) ----
t3 = t2 + timedelta(minutes=9)
rows.append({
    "timestamp": ts(t3), "event_id": "4624", "computer": "dc01",
    "src_host": "srv-file01", "user": "a.sharma", "logon_type": "3",
})

random.shuffle(rows)

fieldnames = ["timestamp", "event_id", "computer", "src_host", "src_ip",
              "dst_ip", "user", "image", "command_line", "destination_port",
              "logon_type", "share", "tier", "role"]
with open("data/sample_logs.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)

print(f"wrote data/sample_logs.csv with {len(rows)} rows")
