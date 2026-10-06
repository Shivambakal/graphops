"""Generate data/sample_logs.csv — realistic Sysmon/4624-style telemetry.

Contains ~200 rows of benign background traffic plus ONE embedded attack
that is NOT labeled in any way:
  - C2 beaconing: a workstation egressing to an external IP on a tight
    ~60s timer (low-jitter) — discoverable only via inter-arrival math.
  - Lateral movement: Logon Type 3 workstation->workstation, then to a
    file server via ADMIN$ — discoverable only via telemetry rules.

Background traffic is deliberately benign: external connections are few
per host (< MIN_BEACONS) with randomized irregular intervals, and no
workstation->workstation Type-3 logons exist outside the attack.
Deterministic (seeded) so tests are reproducible.
"""

from __future__ import annotations

import csv
import random

SEED = 20261005
BASE_EPOCH = 1759564800  # 2026-10-04 16:00:00 UTC

WORKSTATIONS = [f"wkstn-{i:03d}" for i in (11, 12, 13, 21, 22, 31, 32, 41)]
SERVERS = ["srv-file-01", "srv-db-01", "dc-01"]
USERS = ["jdoe", "asmith", "bjones", "kwilson", "tlee", "mgarcia", "pchen", "rpatel"]
EXTERNAL_IPS = ["93.184.216.34", "142.250.190.14", "151.101.193.140",
                "104.16.132.229", "172.67.1.1", "13.107.42.14"]
INTERNAL_NET = "10.0.1."
PROCESSES = [
    (r"C:\Windows\System32\svchost.exe", None),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", None),
    (r"C:\Windows\explorer.exe", None),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", None),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -ExecutionPolicy Bypass -File .\\daily.ps1"),
]

COLUMNS = ["timestamp", "event_id", "computer", "src_host", "dst_host",
           "src_ip", "dst_ip", "user", "logon_type", "image",
           "parent_image", "command_line", "destination_port", "share"]


def ts(epoch: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main() -> None:
    rng = random.Random(SEED)
    rows = []

    host_ip = {h: f"{INTERNAL_NET}{i}" for i, h in enumerate(WORKSTATIONS + SERVERS, start=11)}

    # --- background: morning interactive logons (Type 2 / 11) -----------------
    for i, (user, ws) in enumerate(zip(USERS, WORKSTATIONS)):
        rows.append({
            "timestamp": ts(BASE_EPOCH + rng.randint(0, 1800)),
            "event_id": "4624", "computer": ws, "user": user,
            "logon_type": str(rng.choice([2, 2, 11])),
            "src_ip": host_ip[ws],
        })

    # --- background: process creation noise (Sysmon 1) ------------------------
    for _ in range(55):
        ws = rng.choice(WORKSTATIONS)
        img, cmd = rng.choice(PROCESSES)
        rows.append({
            "timestamp": ts(BASE_EPOCH + rng.randint(0, 14400)),
            "event_id": "1", "computer": ws,
            "user": rng.choice(USERS), "image": img,
            "parent_image": r"C:\Windows\System32\services.exe",
            "command_line": cmd or "",
        })

    # --- background: irregular external web traffic (Sysmon 3) ----------------
    # Deliberately few per host (< beacon threshold) and randomized so the
    # inter-arrival CV stays high — the math must NOT flag these.
    for ws in WORKSTATIONS:
        for _ in range(rng.randint(2, 4)):
            rows.append({
                "timestamp": ts(BASE_EPOCH + rng.randint(0, 14400)),
                "event_id": "3", "computer": ws,
                "image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "src_ip": host_ip[ws],
                "dst_ip": rng.choice(EXTERNAL_IPS),
                "destination_port": "443",
            })

    # --- background: internal traffic -----------------------------------------
    for _ in range(30):
        ws = rng.choice(WORKSTATIONS)
        srv = rng.choice(SERVERS)
        rows.append({
            "timestamp": ts(BASE_EPOCH + rng.randint(0, 14400)),
            "event_id": "3", "computer": ws,
            "image": r"C:\Windows\System32\svchost.exe",
            "src_ip": host_ip[ws],
            "dst_ip": host_ip[srv],
            "destination_port": str(rng.choice([445, 139, 3389])),
        })

    # --- background: legit admin logons to servers (Type 3 ws->server is OK) --
    for _ in range(6):
        rows.append({
            "timestamp": ts(BASE_EPOCH + rng.randint(0, 14400)),
            "event_id": "4624", "computer": rng.choice(SERVERS),
            "src_host": rng.choice(WORKSTATIONS),
            "user": "administrator", "logon_type": "3",
            "src_ip": host_ip[rng.choice(WORKSTATIONS)],
        })

    # === ATTACK (unlabeled) ====================================================
    atk_host = "wkstn-042"
    atk_ip_host = f"{INTERNAL_NET}42"
    c2_ip = "198.51.100.23"  # documentation range; discovered via math, not list
    t0 = BASE_EPOCH + 7200

    # A1: C2 beaconing — tight ~60s timer, +/-1.5s jitter, 14 beacons
    for i in range(14):
        jitter = rng.uniform(-1.5, 1.5)
        rows.append({
            "timestamp": ts(t0 + i * 60 + jitter),
            "event_id": "3", "computer": atk_host,
            "image": r"C:\Windows\System32\svchost.exe",
            "src_ip": atk_ip_host, "dst_ip": c2_ip,
            "destination_port": "443",
        })

    # A2: lateral movement — Type 3 workstation -> workstation
    rows.append({
        "timestamp": ts(t0 + 900), "event_id": "4624",
        "computer": "wkstn-043", "src_host": atk_host,
        "user": "jdoe", "logon_type": "3", "src_ip": atk_ip_host,
    })
    # A3: then to the file server via ADMIN$
    rows.append({
        "timestamp": ts(t0 + 960), "event_id": "4624",
        "computer": "srv-file-01", "src_host": "wkstn-043",
        "user": "jdoe", "logon_type": "3", "src_ip": f"{INTERNAL_NET}43",
        "share": "ADMIN$",
    })
    # A4: payload process spawned on the new foothold
    rows.append({
        "timestamp": ts(t0 + 975), "event_id": "1",
        "computer": "wkstn-043", "user": "jdoe",
        "image": r"C:\Windows\Temp\update.exe",
        "parent_image": r"C:\Windows\System32\svchost.exe",
        "command_line": "update.exe --silent",
    })

    # shuffle so the attack is not positionally obvious
    rng.shuffle(rows)
    with open("data/sample_logs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to data/sample_logs.csv")


if __name__ == "__main__":
    main()
