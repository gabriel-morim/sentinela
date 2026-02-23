"""
Sentinela - AI Analyst (Phase 2)
Connects Claude to the event store to generate:
  - Threat narratives for suspicious activity clusters
  - Shift summaries (what happened in the last N hours)
  - Baseline anomaly detection
  - Network configuration suggestions

Usage:
    python analyst/analyze.py --summary          # shift summary
    python analyst/analyze.py --threats          # threat narratives
    python analyst/analyze.py --ip 185.220.101.1 # investigate specific IP
    python analyst/analyze.py --full             # full analysis
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from elasticsearch import Elasticsearch
import anthropic
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

ES_HOST      = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX     = os.getenv("ES_INDEX", "sentinela-events")
LOOKBACK_MIN = int(os.getenv("LOOKBACK_MINUTES", "120"))
MAX_EVENTS   = int(os.getenv("MAX_EVENTS_PER_ANALYSIS", "100"))
API_KEY      = os.getenv("ANTHROPIC_API_KEY")

BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"

# ─── Elasticsearch helpers ────────────────────────────────────────────────────

def get_es():
    return Elasticsearch(ES_HOST)


def fetch_recent_events(minutes: int = LOOKBACK_MIN, size: int = MAX_EVENTS) -> list[dict]:
    """Fetch recent events from Elasticsearch, prioritising high severity."""
    es = get_es()
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = es.search(index=ES_INDEX, body={
        "query": {"range": {"timestamp": {"gte": since}}},
        "sort": [
            {"severity": {"order": "desc"}},
            {"timestamp": {"order": "desc"}}
        ],
        "size": size
    })
    return [h["_source"] for h in result["hits"]["hits"]]


def fetch_events_for_ip(ip: str, minutes: int = 1440) -> list[dict]:
    """Fetch all events involving a specific IP address."""
    es = get_es()
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = es.search(index=ES_INDEX, body={
        "query": {
            "bool": {
                "must": [{"range": {"timestamp": {"gte": since}}}],
                "should": [
                    {"term": {"src_ip": ip}},
                    {"term": {"dst_ip": ip}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"timestamp": {"order": "asc"}}],
        "size": 200
    })
    return [h["_source"] for h in result["hits"]["hits"]]


def fetch_severity_counts(minutes: int = LOOKBACK_MIN) -> dict:
    """Get event counts broken down by severity."""
    es = get_es()
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = es.search(index=ES_INDEX, body={
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {
            "by_severity": {"terms": {"field": "severity"}},
            "by_type":     {"terms": {"field": "source_type"}},
            "by_tag":      {"terms": {"field": "tags", "size": 20}},
            "top_src_ips": {
                "filter": {"terms": {"severity": ["high", "critical"]}},
                "aggs": {"ips": {"terms": {"field": "src_ip", "size": 10}}}
            }
        },
        "size": 0
    })

    aggs = result["aggregations"]
    return {
        "severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
        "source_type": {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]},
        "tags": {b["key"]: b["doc_count"] for b in aggs["by_tag"]["buckets"]},
        "top_threat_ips": [b["key"] for b in aggs["top_src_ips"]["ips"]["buckets"]],
    }


def group_events_by_ip(events: list[dict]) -> dict[str, list]:
    """Group events by source IP for clustering."""
    groups = defaultdict(list)
    for e in events:
        ip = e.get("src_ip")
        if ip:
            groups[ip].append(e)
    return dict(groups)


# ─── Event formatting for LLM context ────────────────────────────────────────

def format_events_for_prompt(events: list[dict], max_events: int = 60) -> str:
    """Convert events to a compact text representation for the LLM."""
    lines = []
    for e in events[:max_events]:
        ts    = e.get("timestamp", "")[:19].replace("T", " ")
        stype = e.get("source_type", "").upper()
        sev   = e.get("severity", "").upper()
        src   = e.get("src_ip") or "-"
        dst   = e.get("dst_ip") or "-"
        dport = e.get("dst_port") or "-"
        msg   = e.get("message", "")
        tags  = ",".join(e.get("tags", []))
        tags_str = f" [{tags}]" if tags else ""
        lines.append(f"{ts} | {sev:<8} | {stype:<8} | {src} -> {dst}:{dport} | {msg}{tags_str}")
    return "\n".join(lines)


# ─── Claude API calls ─────────────────────────────────────────────────────────

def call_claude(system_prompt: str, user_prompt: str) -> str:
    """Call the Claude API and return the response text."""
    if not API_KEY:
        return "[ERROR] ANTHROPIC_API_KEY not set in .env file."

    client = anthropic.Anthropic(api_key=API_KEY)
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1500,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )
    return message.content[0].text


SYSTEM_PROMPT = """You are Sentinela, an AI security analyst embedded in a network security operations system.

You have access to normalized security events from firewalls, IDS sensors, authentication logs, and syslog.

Your job is to:
- Identify real threats from the noise, clearly and concisely
- Explain what is happening in plain language a non-specialist can understand
- Connect related events into coherent attack narratives when the evidence supports it
- Suggest specific, actionable responses
- Be honest about your confidence level — say when something is suspicious but not confirmed

You are not alarmist. You do not cry wolf. You focus on what the evidence actually shows.
Format your responses clearly with sections. Use plain language. Be direct."""


# ─── Analysis functions ───────────────────────────────────────────────────────

def generate_shift_summary(minutes: int = LOOKBACK_MIN) -> str:
    """Generate a natural language summary of recent activity."""
    events = fetch_recent_events(minutes=minutes, size=MAX_EVENTS)
    counts = fetch_severity_counts(minutes=minutes)

    if not events:
        return "No events found in the specified time window."

    event_text = format_events_for_prompt(events)

    prompt = f"""Here is a summary of security events from the last {minutes} minutes:

COUNTS:
{json.dumps(counts, indent=2)}

EVENTS (most severe first, up to {MAX_EVENTS}):
{event_text}

Please provide a shift summary covering:
1. OVERALL SITUATION — one paragraph on what the network looks like right now
2. KEY THREATS — the most important things that need attention, in priority order
3. NOTABLE PATTERNS — anything interesting even if not immediately dangerous
4. RECOMMENDED ACTIONS — specific things the operator should do right now

Keep it concise and actionable. This will be read by an IT professional at the start of their shift."""

    return call_claude(SYSTEM_PROMPT, prompt)


def generate_threat_narratives(minutes: int = LOOKBACK_MIN) -> str:
    """Identify and narrate threat scenarios from recent events."""
    events = fetch_recent_events(minutes=minutes, size=MAX_EVENTS)

    if not events:
        return "No events found in the specified time window."

    # Focus on suspicious events
    suspicious = [
        e for e in events
        if e.get("severity") in ("high", "critical")
        or "threat_intel_match" in e.get("tags", [])
        or "ids_alert" in e.get("tags", [])
        or "port_scan" in e.get("tags", [])
        or "lateral_movement" in e.get("tags", [])
    ]

    if not suspicious:
        return "No high-severity or suspicious events found in this time window."

    # Group by source IP to identify campaigns
    by_ip = group_events_by_ip(suspicious)
    event_text = format_events_for_prompt(suspicious, max_events=80)

    prompt = f"""I need you to analyze these suspicious security events and identify distinct threat scenarios.

SUSPICIOUS EVENTS ({len(suspicious)} total):
{event_text}

SOURCE IP GROUPS:
{json.dumps({ip: len(evts) for ip, evts in by_ip.items()}, indent=2)}

For each distinct threat scenario you identify, provide:
- SCENARIO NAME (short, descriptive)
- WHAT HAPPENED (2-3 sentences telling the story of what the attacker did)
- EVIDENCE (the specific events that support this conclusion)
- AFFECTED SYSTEMS (which internal hosts are involved)
- SEVERITY ASSESSMENT (critical/high/medium and why)
- RECOMMENDED RESPONSE (specific actions, in order)
- CONFIDENCE LEVEL (high/medium/low and why)

If events appear to be related (same attacker, same campaign), connect them into one narrative rather than treating them separately."""

    return call_claude(SYSTEM_PROMPT, prompt)


def investigate_ip(ip: str) -> str:
    """Deep dive investigation of a specific IP address."""
    events = fetch_events_for_ip(ip)

    if not events:
        return f"No events found involving IP {ip} in the last 24 hours."

    event_text = format_events_for_prompt(events, max_events=100)

    prompt = f"""I need a full investigation report on IP address {ip}.

ALL EVENTS INVOLVING THIS IP (chronological):
{event_text}

Please provide:
1. IP PROFILE — What do we know about this IP? Is it internal or external? Is it in threat intel feeds (look for threat_intel_match tags)?
2. ACTIVITY TIMELINE — Walk through what this IP did, in chronological order
3. THREAT ASSESSMENT — Is this IP malicious, suspicious, or benign? What is the evidence?
4. ATTACK TECHNIQUE — If malicious, what technique are they using? (brute force, scanning, exfiltration, etc.)
5. IMPACT — What systems were affected or potentially compromised?
6. RECOMMENDED ACTIONS — What should the operator do about this IP right now?"""

    return call_claude(SYSTEM_PROMPT, prompt)


def generate_config_suggestions(minutes: int = LOOKBACK_MIN) -> str:
    """Suggest network configuration changes based on observed activity."""
    events = fetch_recent_events(minutes=minutes, size=MAX_EVENTS)
    counts = fetch_severity_counts(minutes=minutes)

    if not events:
        return "No events to base suggestions on."

    suspicious = [
        e for e in events
        if e.get("severity") in ("high", "critical")
        or "threat_intel_match" in e.get("tags", [])
    ]

    event_text = format_events_for_prompt(suspicious[:50])

    prompt = f"""Based on the following security events, suggest specific network configuration changes.

HIGH/CRITICAL EVENTS:
{event_text}

TOP THREAT IPs: {counts.get('top_threat_ips', [])}

For each suggestion provide:
- CHANGE TYPE (firewall rule / rate limit / VLAN change / etc.)
- SPECIFIC RULE OR CONFIG (write the actual rule, e.g. iptables syntax or plain description)
- REASON (what event or pattern justifies this change)
- RISK (any side effects the operator should know about before applying)
- PRIORITY (apply immediately / apply soon / consider for future)

Focus on concrete, specific changes — not generic advice. Write rules the operator can actually implement."""

    return call_claude(SYSTEM_PROMPT, prompt)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  SENTINELA — {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Sentinela AI Analyst")
    parser.add_argument("--summary",  action="store_true", help="Generate shift summary")
    parser.add_argument("--threats",  action="store_true", help="Generate threat narratives")
    parser.add_argument("--ip",       type=str,            help="Investigate a specific IP")
    parser.add_argument("--config",   action="store_true", help="Suggest config changes")
    parser.add_argument("--full",     action="store_true", help="Run full analysis (all of the above)")
    parser.add_argument("--last",     type=int, default=LOOKBACK_MIN, help="Lookback window in minutes")
    args = parser.parse_args()

    if not any([args.summary, args.threats, args.ip, args.config, args.full]):
        parser.print_help()
        return

    if args.full or args.summary:
        print_header("Shift Summary")
        print(generate_shift_summary(minutes=args.last))

    if args.full or args.threats:
        print_header("Threat Narratives")
        print(generate_threat_narratives(minutes=args.last))

    if args.ip:
        print_header(f"IP Investigation: {args.ip}")
        print(investigate_ip(args.ip))

    if args.full or args.config:
        print_header("Configuration Suggestions")
        print(generate_config_suggestions(minutes=args.last))


if __name__ == "__main__":
    main()