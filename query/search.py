"""
Sentinela - Query CLI
Search and explore normalized events from the command line.
Usage:
    python search.py                          # show last 20 events
    python search.py --severity high          # filter by severity
    python search.py --src-ip 45.33.32.156   # filter by source IP
    python search.py --tag threat_intel_match # filter by tag
    python search.py --type ids               # filter by source type
    python search.py --last 60               # last N minutes
    python search.py --summary               # print a summary dashboard
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
INDEX_NAME = "sentinela-events"

SEVERITY_COLOR = {
    "info":     "\033[37m",    # white
    "low":      "\033[34m",    # blue
    "medium":   "\033[33m",    # yellow
    "high":     "\033[91m",    # bright red
    "critical": "\033[41m",    # red background
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def color(text: str, severity: str) -> str:
    c = SEVERITY_COLOR.get(severity, "")
    return f"{c}{text}{RESET}"


def format_event(e: dict) -> str:
    sev   = e.get("severity", "info")
    ts    = e.get("timestamp", "")[:19].replace("T", " ")
    stype = e.get("source_type", "").upper().ljust(8)
    src   = e.get("src_ip") or "-"
    dst   = e.get("dst_ip") or "-"
    dport = e.get("dst_port") or "-"
    msg   = e.get("message", "")[:80]
    tags  = ",".join(e.get("tags", []))
    tags_str = f" [{tags}]" if tags else ""
    sev_str = sev.upper().ljust(8)

    line = f"{ts}  {color(sev_str, sev)}  {stype}  {src} -> {dst}:{dport}  {msg}{tags_str}"
    return line


def search(
    severity: str = None,
    src_ip: str = None,
    tag: str = None,
    source_type: str = None,
    last_minutes: int = 120,
    size: int = 20,
) -> list[dict]:
    es = Elasticsearch(ES_HOST)

    must = []

    # Time filter
    since = (datetime.now(timezone.utc) - timedelta(minutes=last_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    must.append({"range": {"timestamp": {"gte": since}}})

    if severity:
        must.append({"term": {"severity": severity}})
    if src_ip:
        must.append({"term": {"src_ip": src_ip}})
    if tag:
        must.append({"term": {"tags": tag}})
    if source_type:
        must.append({"term": {"source_type": source_type}})

    query = {"bool": {"must": must}}

    result = es.search(
        index=INDEX_NAME,
        body={
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }
    )

    return [hit["_source"] for hit in result["hits"]["hits"]]


def print_summary():
    """Print a dashboard-style summary of recent events."""
    es = Elasticsearch(ES_HOST)

    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_query = {"range": {"timestamp": {"gte": since}}}

    # Count by severity
    sev_agg = es.search(index=INDEX_NAME, body={
        "query": base_query,
        "aggs": {"by_severity": {"terms": {"field": "severity", "size": 10}}},
        "size": 0
    })

    # Count by tag
    tag_agg = es.search(index=INDEX_NAME, body={
        "query": base_query,
        "aggs": {"by_tag": {"terms": {"field": "tags", "size": 10}}},
        "size": 0
    })

    # Top source IPs
    ip_agg = es.search(index=INDEX_NAME, body={
        "query": {"bool": {"must": [base_query, {"terms": {"severity": ["high", "critical"]}}]}},
        "aggs": {"top_ips": {"terms": {"field": "src_ip", "size": 5}}},
        "size": 0
    })

    # Total
    total = es.count(index=INDEX_NAME, body={"query": base_query})["count"]

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SENTINELA — Event Summary (last 24 hours){RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Total events:  {total}")
    print()

    print(f"{BOLD}  By Severity:{RESET}")
    for bucket in sev_agg["aggregations"]["by_severity"]["buckets"]:
        k = bucket["key"]
        v = bucket["doc_count"]
        bar = "█" * min(v // 5, 40)
        print(f"    {color(k.upper().ljust(10), k)} {v:>6}  {bar}")

    print()
    print(f"{BOLD}  Notable Tags:{RESET}")
    for bucket in tag_agg["aggregations"]["by_tag"]["buckets"]:
        if bucket["key"] not in ("unparsed",):
            print(f"    {bucket['key'].ljust(30)} {bucket['doc_count']}")

    print()
    print(f"{BOLD}  Top High/Critical Source IPs:{RESET}")
    for bucket in ip_agg["aggregations"]["top_ips"]["buckets"]:
        print(f"    {bucket['key'].ljust(20)} {bucket['doc_count']} events")

    print(f"\n{BOLD}{'='*60}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Sentinela event search")
    parser.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    parser.add_argument("--src-ip", dest="src_ip")
    parser.add_argument("--tag")
    parser.add_argument("--type", dest="source_type", choices=["syslog", "firewall", "ids", "auth", "endpoint"])
    parser.add_argument("--last", dest="last_minutes", type=int, default=120, help="Last N minutes (default 120)")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--summary", action="store_true", help="Print summary dashboard")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.summary:
        print_summary()
        return

    events = search(
        severity=args.severity,
        src_ip=args.src_ip,
        tag=args.tag,
        source_type=args.source_type,
        last_minutes=args.last_minutes,
        size=args.limit,
    )

    if not events:
        print("No events found matching your filters.")
        return

    if args.json:
        print(json.dumps(events, indent=2))
        return

    print(f"\n  {'TIMESTAMP'.ljust(19)}  {'SEVERITY'.ljust(8)}  {'TYPE'.ljust(8)}  {'SRC -> DST:PORT'.ljust(28)}  MESSAGE")
    print("  " + "-" * 110)
    for e in reversed(events):
        print("  " + format_event(e))
    print(f"\n  {len(events)} events shown.\n")


if __name__ == "__main__":
    main()