"""
Sentinela - Synthetic Log Generator
Generates realistic fake logs simulating a small corporate network.
Includes: syslog, firewall, IDS/IPS, and auth events.
Mix of normal traffic and seeded threat scenarios for testing.
"""

import random
import uuid
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Generator

# ─── Network topology for our fake company ───────────────────────────────────

INTERNAL_HOSTS = {
    "192.168.1.10": "web-server-01",
    "192.168.1.11": "web-server-02",
    "192.168.1.20": "db-server-01",
    "192.168.1.21": "db-server-02",
    "192.168.1.30": "fileserver-01",
    "192.168.1.100": "workstation-alice",
    "192.168.1.101": "workstation-bob",
    "192.168.1.102": "workstation-carol",
    "192.168.1.103": "workstation-dave",
    "192.168.1.1":   "gateway-fw-01",
}

EXTERNAL_LEGIT_IPS = [
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "151.101.1.140",                 # Fastly CDN
    "54.230.10.1",                   # AWS CloudFront
    "104.21.50.100",                 # Cloudflare hosted
]

KNOWN_BAD_IPS = [
    "45.33.32.156",   # Known scanner (Shodan)
    "185.220.101.1",  # Tor exit node
    "194.165.16.11",  # Known C2
    "103.75.190.1",   # Malware distribution
]

USERS = ["alice", "bob", "carol", "dave", "admin", "svc_backup", "svc_monitor"]

COMMON_PORTS = {
    80: "http", 443: "https", 22: "ssh", 3306: "mysql",
    5432: "postgres", 445: "smb", 3389: "rdp", 53: "dns",
    25: "smtp", 110: "pop3", 143: "imap"
}


def random_timestamp(minutes_ago_max: int = 60) -> str:
    """Generate a random recent UTC timestamp."""
    delta = timedelta(seconds=random.randint(0, minutes_ago_max * 60))
    t = datetime.now(timezone.utc) - delta
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def random_internal_ip() -> str:
    return random.choice(list(INTERNAL_HOSTS.keys()))


def random_external_ip(include_bad: bool = False) -> str:
    if include_bad and random.random() < 0.15:
        return random.choice(KNOWN_BAD_IPS)
    return random.choice(EXTERNAL_LEGIT_IPS)


# ─── Individual log generators ───────────────────────────────────────────────

def gen_firewall_allow() -> str:
    src = random_external_ip()
    dst = random_internal_ip()
    sport = random.randint(1024, 65535)
    dport = random.choice(list(COMMON_PORTS.keys()))
    proto = "TCP" if dport != 53 else "UDP"
    ts = random_timestamp()
    return (
        f"{ts} gateway-fw-01 kernel: ALLOW IN=eth0 OUT=eth1 "
        f"SRC={src} DST={dst} SPORT={sport} DPORT={dport} PROTO={proto}"
    )


def gen_firewall_deny() -> str:
    src = random_external_ip(include_bad=True)
    dst = random_internal_ip()
    sport = random.randint(1024, 65535)
    dport = random.choice([22, 3389, 445, 3306, 5432, 8080, 8443])
    ts = random_timestamp()
    return (
        f"{ts} gateway-fw-01 kernel: DENY IN=eth0 OUT=eth1 "
        f"SRC={src} DST={dst} SPORT={sport} DPORT={dport} PROTO=TCP"
    )


def gen_syslog_normal() -> str:
    host = random.choice(list(INTERNAL_HOSTS.values()))
    messages = [
        "systemd: Started Daily apt download activities.",
        "sshd: Server listening on 0.0.0.0 port 22.",
        "cron: pam_unix(cron:session): session opened for user root",
        "kernel: eth0: renamed from veth3a2b1c",
        "rsyslogd: imjournal: journal files changed, reloading",
        "ntpd: Soliciting pool server 162.159.200.1",
        "postfix/pickup: startup",
        "anacron: Job 'cron.daily' started",
        "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/systemctl status nginx",
    ]
    ts = random_timestamp()
    msg = random.choice(messages)
    return f"{ts} {host} {msg}"


def gen_auth_success() -> str:
    user = random.choice(USERS)
    host = random.choice(list(INTERNAL_HOSTS.values()))
    src = random_internal_ip()
    ts = random_timestamp()
    return (
        f"{ts} {host} sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {user} from {src} port {random.randint(1024,65535)} ssh2"
    )


def gen_auth_failure() -> str:
    user = random.choice(USERS + ["root", "administrator", "test", "guest"])
    host = random.choice(list(INTERNAL_HOSTS.values()))
    src = random_external_ip(include_bad=True)
    ts = random_timestamp()
    return (
        f"{ts} {host} sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {user} from {src} port {random.randint(1024,65535)} ssh2"
    )


def gen_ids_alert() -> str:
    signatures = [
        ("ET SCAN Nmap SYN Scan", "high", "2000537"),
        ("ET POLICY SSH Outbound", "medium", "2001219"),
        ("ET MALWARE Known Malicious SSL Cert", "critical", "2023476"),
        ("ET SCAN XMAS Scan", "medium", "2000543"),
        ("ET EXPLOIT SMB MS17-010 EternalBlue", "critical", "2024218"),
        ("ET TROJAN Generic Backdoor", "high", "2019401"),
        ("ET INFO DNS Query to Suspicious TLD", "low", "2027863"),
        ("ET SCAN Port Scan Detected", "medium", "2010937"),
    ]
    sig_name, severity, sid = random.choice(signatures)
    src = random_external_ip(include_bad=True)
    dst = random_internal_ip()
    dport = random.choice(list(COMMON_PORTS.keys()))
    ts = random_timestamp()
    return (
        f"{ts} ids-sensor-01 snort[1234]: [1:{sid}:1] {sig_name} "
        f"[Classification: Attempted Information Leak] [Priority: 2] "
        f"{{TCP}} {src}:{random.randint(1024,65535)} -> {dst}:{dport}"
    )


# ─── Threat scenarios ─────────────────────────────────────────────────────────
# These inject sequences of related events that tell a story.

def gen_brute_force_sequence(attacker_ip: str = None, target_host: str = None) -> list[str]:
    """Simulate a brute force SSH attack followed by a successful login."""
    attacker = attacker_ip or random.choice(KNOWN_BAD_IPS)
    target = target_host or random.choice(["web-server-01", "web-server-02"])
    base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(5, 30))
    logs = []

    # 20 failed attempts
    for i in range(20):
        t = (base_time + timedelta(seconds=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        user = random.choice(["root", "admin", "ubuntu", "deploy"])
        logs.append(
            f"{t} {target} sshd[4821]: Failed password for {user} "
            f"from {attacker} port {random.randint(1024,65535)} ssh2"
        )

    # IDS picks it up
    t = (base_time + timedelta(seconds=65)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(
        f"{t} ids-sensor-01 snort[1234]: [1:2010937:1] ET SCAN SSH BruteForce "
        f"[Priority: 2] {{TCP}} {attacker}:54321 -> 192.168.1.11:22"
    )

    # Then a success (credential stuffing worked)
    t = (base_time + timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(
        f"{t} {target} sshd[4821]: Accepted password for root "
        f"from {attacker} port {random.randint(1024,65535)} ssh2"
    )

    return logs


def gen_lateral_movement_sequence(compromised_ip: str = None) -> list[str]:
    """Simulate lateral movement after an initial compromise."""
    pivot = compromised_ip or "192.168.1.11"
    pivot_name = INTERNAL_HOSTS.get(pivot, "compromised-host")
    targets = [ip for ip in INTERNAL_HOSTS if ip != pivot and ip != "192.168.1.1"]
    base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(2, 15))
    logs = []

    # Internal port scan
    for i, target in enumerate(random.sample(targets, min(5, len(targets)))):
        t = (base_time + timedelta(seconds=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dport = random.choice([22, 445, 3389, 3306])
        logs.append(
            f"{t} gateway-fw-01 kernel: DENY IN=eth1 OUT=eth1 "
            f"SRC={pivot} DST={target} SPORT=54000 DPORT={dport} PROTO=TCP"
        )

    # IDS fires on the internal scan
    t = (base_time + timedelta(seconds=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(
        f"{t} ids-sensor-01 snort[1234]: [1:2000537:1] ET SCAN Nmap SYN Scan "
        f"[Priority: 2] {{TCP}} {pivot}:54000 -> 192.168.1.20:3306"
    )

    # Successful connection to DB
    t = (base_time + timedelta(seconds=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(
        f"{t} gateway-fw-01 kernel: ALLOW IN=eth1 OUT=eth1 "
        f"SRC={pivot} DST=192.168.1.20 SPORT=54100 DPORT=3306 PROTO=TCP"
    )

    return logs


def gen_data_exfil_sequence(src_ip: str = None) -> list[str]:
    """Simulate large outbound data transfer to a suspicious IP."""
    src = src_ip or "192.168.1.20"
    dst = random.choice(KNOWN_BAD_IPS)
    base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 10))
    logs = []

    # Multiple large outbound connections
    for i in range(6):
        t = (base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        bytes_out = random.randint(500000, 2000000)
        logs.append(
            f"{t} gateway-fw-01 kernel: ALLOW IN=eth1 OUT=eth0 "
            f"SRC={src} DST={dst} SPORT={50000+i} DPORT=443 PROTO=TCP BYTES={bytes_out}"
        )

    # IDS alert on exfil
    t = (base_time + timedelta(seconds=65)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(
        f"{t} ids-sensor-01 snort[1234]: [1:2019401:1] ET TROJAN Possible Data Exfiltration "
        f"Large Outbound [Priority: 1] {{TCP}} {src}:50000 -> {dst}:443"
    )

    return logs


# ─── Main generator ───────────────────────────────────────────────────────────

def generate_log_stream(
    count: int = 500,
    inject_threats: bool = True
) -> Generator[str, None, None]:
    """
    Generate a stream of mixed log lines.
    Roughly: 70% normal traffic, 20% suspicious/denied, 10% threat scenarios.
    """
    normal_generators = [
        gen_firewall_allow,
        gen_firewall_allow,
        gen_firewall_allow,   # weight: more allow than deny in normal traffic
        gen_firewall_deny,
        gen_syslog_normal,
        gen_syslog_normal,
        gen_auth_success,
        gen_auth_failure,
    ]

    # Inject threat sequences at random points
    threat_sequences = []
    if inject_threats:
        threat_sequences.extend(gen_brute_force_sequence())
        threat_sequences.extend(gen_lateral_movement_sequence())
        threat_sequences.extend(gen_data_exfil_sequence())
        random.shuffle(threat_sequences)

    threat_index = 0
    threat_inject_points = sorted(random.sample(range(count), min(len(threat_sequences), count)))

    for i in range(count):
        if threat_inject_points and i == threat_inject_points[0] and threat_index < len(threat_sequences):
            yield threat_sequences[threat_index]
            threat_index += 1
            threat_inject_points.pop(0)
        else:
            gen_fn = random.choice(normal_generators)
            yield gen_fn()

        time.sleep(0)  # no sleep in batch mode


def generate_to_file(output_path: str, count: int = 500):
    """Write synthetic logs to a file."""
    print(f"[sentinela-generator] Writing {count} synthetic log lines to {output_path}...")
    with open(output_path, "w") as f:
        for line in generate_log_stream(count=count, inject_threats=True):
            f.write(line + "\n")
    print(f"[sentinela-generator] Done. File ready at {output_path}")


if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "synthetic_logs.txt"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    generate_to_file(output, count)