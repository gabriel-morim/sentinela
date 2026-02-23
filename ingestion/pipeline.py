"""
Sentinela - Ingestion Pipeline
Reads raw log lines, normalizes them to the unified schema,
and indexes them into Elasticsearch.
"""

import re
import uuid
import json
import sys
import time
from datetime import datetime, timezone
from typing import Optional
from elasticsearch import Elasticsearch, helpers

# ─── Config ───────────────────────────────────────────────────────────────────

ES_HOST = "http://localhost:9200"
INDEX_NAME = "sentinela-events"

KNOWN_BAD_IPS = {
    "45.33.32.156", "185.220.101.1", "194.165.16.11", "103.75.190.1"
}

# ─── Elasticsearch setup ──────────────────────────────────────────────────────

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "event_id":     {"type": "keyword"},
            "timestamp":    {"type": "date"},
            "ingested_at":  {"type": "date"},
            "source_type":  {"type": "keyword"},
            "source_host":  {"type": "keyword"},
            "severity":     {"type": "keyword"},
            "category":     {"type": "keyword"},
            "action":       {"type": "keyword"},
            "src_ip":       {"type": "ip"},
            "src_port":     {"type": "integer"},
            "dst_ip":       {"type": "ip"},
            "dst_port":     {"type": "integer"},
            "protocol":     {"type": "keyword"},
            "user":         {"type": "keyword"},
            "process":      {"type": "keyword"},
            "message":      {"type": "text"},
            "tags":         {"type": "keyword"},
            "raw":          {"type": "text"},
        }
    }
}


def get_es_client() -> Elasticsearch:
    return Elasticsearch(ES_HOST)


def ensure_index(es: Elasticsearch):
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
        print(f"[pipeline] Created index: {INDEX_NAME}")
    else:
        print(f"[pipeline] Index already exists: {INDEX_NAME}")


# ─── Parsers ──────────────────────────────────────────────────────────────────

def parse_firewall(raw: str) -> Optional[dict]:
    """Parse iptables-style firewall logs."""
    pattern = re.compile(
        r"(?P<timestamp>\S+T\S+)\s+(?P<host>\S+)\s+kernel:\s+"
        r"(?P<action>ALLOW|DENY)\s+.*?"
        r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+"
        r"(?:SPORT=(?P<src_port>\d+)\s+)?DPORT=(?P<dst_port>\d+)\s+PROTO=(?P<proto>\S+)"
        r"(?:\s+BYTES=(?P<bytes>\d+))?"
    )
    m = pattern.search(raw)
    if not m:
        return None

    action = m.group("action").lower()
    dst_port = int(m.group("dst_port"))
    src_ip = m.group("src_ip")

    # Severity logic
    if action == "deny" and dst_port in (22, 3389, 445, 3306):
        severity = "medium"
    elif action == "deny" and src_ip in KNOWN_BAD_IPS:
        severity = "high"
    elif action == "deny":
        severity = "low"
    else:
        severity = "info"

    tags = []
    if src_ip in KNOWN_BAD_IPS:
        tags.append("threat_intel_match")
    if int(m.group("bytes") or 0) > 1000000:
        tags.append("large_transfer")

    return {
        "source_type": "firewall",
        "source_host": m.group("host"),
        "timestamp": m.group("timestamp"),
        "severity": severity,
        "category": "firewall",
        "action": action,
        "src_ip": src_ip,
        "src_port": int(m.group("src_port")) if m.group("src_port") else None,
        "dst_ip": m.group("dst_ip"),
        "dst_port": dst_port,
        "protocol": m.group("proto").lower(),
        "message": f"Firewall {action} from {src_ip} to {m.group('dst_ip')}:{dst_port}",
        "tags": tags,
    }


def parse_syslog(raw: str) -> Optional[dict]:
    """Parse generic syslog lines."""
    pattern = re.compile(
        r"(?P<timestamp>\S+T\S+)\s+(?P<host>\S+)\s+(?P<process>[^:\[]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)"
    )
    m = pattern.search(raw)
    if not m:
        return None

    process = m.group("process").strip()
    message = m.group("message").strip()

    # Detect sudo usage
    severity = "info"
    tags = []
    category = "system"
    if "sudo" in process.lower():
        severity = "low"
        tags.append("privilege_escalation")
        category = "authentication"

    return {
        "source_type": "syslog",
        "source_host": m.group("host"),
        "timestamp": m.group("timestamp"),
        "severity": severity,
        "category": category,
        "action": "log",
        "process": process,
        "message": message[:200],
        "tags": tags,
    }


def parse_auth(raw: str) -> Optional[dict]:
    """Parse SSH auth events."""
    # Success
    success_pattern = re.compile(
        r"(?P<timestamp>\S+T\S+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Accepted password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
    )
    # Failure
    failure_pattern = re.compile(
        r"(?P<timestamp>\S+T\S+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
    )

    m = success_pattern.search(raw)
    if m:
        tags = []
        if m.group("src_ip") in KNOWN_BAD_IPS:
            tags.append("threat_intel_match")
        return {
            "source_type": "auth",
            "source_host": m.group("host"),
            "timestamp": m.group("timestamp"),
            "severity": "info",
            "category": "authentication",
            "action": "login_success",
            "src_ip": m.group("src_ip"),
            "src_port": int(m.group("src_port")),
            "dst_port": 22,
            "protocol": "ssh",
            "user": m.group("user"),
            "message": f"Successful SSH login for {m.group('user')} from {m.group('src_ip')}",
            "tags": tags,
        }

    m = failure_pattern.search(raw)
    if m:
        src_ip = m.group("src_ip")
        severity = "high" if src_ip in KNOWN_BAD_IPS else "medium"
        tags = ["login_failure"]
        if src_ip in KNOWN_BAD_IPS:
            tags.append("threat_intel_match")
        return {
            "source_type": "auth",
            "source_host": m.group("host"),
            "timestamp": m.group("timestamp"),
            "severity": severity,
            "category": "authentication",
            "action": "login_failure",
            "src_ip": src_ip,
            "src_port": int(m.group("src_port")),
            "dst_port": 22,
            "protocol": "ssh",
            "user": m.group("user"),
            "message": f"Failed SSH login for {m.group('user')} from {src_ip}",
            "tags": tags,
        }

    return None


def parse_ids(raw: str) -> Optional[dict]:
    """Parse Snort/Suricata IDS alert lines."""
    pattern = re.compile(
        r"(?P<timestamp>\S+T\S+)\s+\S+\s+snort\[\d+\]:\s+"
        r"\[1:(?P<sid>\d+):\d+\]\s+(?P<signature>[^\[]+)"
        r".*?\{(?P<proto>\w+)\}\s+"
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+"
        r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)"
    )
    m = pattern.search(raw)
    if not m:
        return None

    sig = m.group("signature").strip()

    # Map signature keywords to severity
    severity = "medium"
    if any(k in sig.upper() for k in ["CRITICAL", "EXPLOIT", "TROJAN", "BACKDOOR", "ETERNAL"]):
        severity = "critical"
    elif any(k in sig.upper() for k in ["MALWARE", "C2", "EXFIL"]):
        severity = "high"
    elif "SCAN" in sig.upper():
        severity = "medium"
    elif "INFO" in sig.upper() or "POLICY" in sig.upper():
        severity = "low"

    tags = ["ids_alert"]
    src_ip = m.group("src_ip")
    if src_ip in KNOWN_BAD_IPS:
        tags.append("threat_intel_match")
    if "scan" in sig.lower():
        tags.append("port_scan")
    if "lateral" in sig.lower() or "smb" in sig.lower():
        tags.append("lateral_movement")

    return {
        "source_type": "ids",
        "source_host": "ids-sensor-01",
        "timestamp": m.group("timestamp"),
        "severity": severity,
        "category": "intrusion_detection",
        "action": "alert",
        "src_ip": src_ip,
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst_ip"),
        "dst_port": int(m.group("dst_port")),
        "protocol": m.group("proto").lower(),
        "message": f"IDS Alert: {sig}",
        "tags": tags,
    }


# ─── Normalizer ───────────────────────────────────────────────────────────────

PARSERS = [parse_auth, parse_ids, parse_firewall, parse_syslog]


def normalize(raw: str) -> Optional[dict]:
    """Try each parser in order, return the first successful parse."""
    raw = raw.strip()
    if not raw:
        return None

    for parser in PARSERS:
        result = parser(raw)
        if result:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            result["event_id"] = str(uuid.uuid4())
            result["ingested_at"] = now
            result["raw"] = raw
            if "tags" not in result:
                result["tags"] = []
            return result

    # Fallback: store as unparsed syslog
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_type": "syslog",
        "source_host": "unknown",
        "severity": "info",
        "category": "system",
        "action": "log",
        "message": raw[:200],
        "tags": ["unparsed"],
        "raw": raw,
    }


# ─── Main ingestion ───────────────────────────────────────────────────────────

def ingest_file(filepath: str, batch_size: int = 100):
    """Read a log file and bulk-index all events into Elasticsearch."""
    es = get_es_client()

    # Wait for ES to be ready
    for attempt in range(10):
        try:
            es.cluster.health(wait_for_status="yellow", timeout="5s")
            break
        except Exception:
            print(f"[pipeline] Waiting for Elasticsearch... ({attempt+1}/10)")
            time.sleep(3)
    else:
        print("[pipeline] ERROR: Could not connect to Elasticsearch at", ES_HOST)
        sys.exit(1)

    ensure_index(es)

    total = 0
    errors = 0
    batch = []

    print(f"[pipeline] Ingesting {filepath}...")

    with open(filepath, "r") as f:
        for line in f:
            event = normalize(line)
            if event:
                batch.append({
                    "_index": INDEX_NAME,
                    "_id": event["event_id"],
                    "_source": event,
                })
                total += 1

            if len(batch) >= batch_size:
                success, failed = helpers.bulk(es, batch, raise_on_error=False)
                errors += len(failed)
                batch = []
                print(f"[pipeline] Indexed {total} events...", end="\r")

    # Final batch
    if batch:
        helpers.bulk(es, batch, raise_on_error=False)

    print(f"\n[pipeline] Done. {total} events indexed, {errors} errors.")
    print(f"[pipeline] View in Kibana: http://localhost:5601")


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "synthetic_logs.txt"
    ingest_file(filepath)