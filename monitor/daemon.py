"""
Sentinela - Continuous Monitor
Watches Elasticsearch for new threats and fires alerts automatically.

Usage:
    python monitor/daemon.py              # run with default 60s interval
    python monitor/daemon.py --interval 30  # check every 30 seconds
    python monitor/daemon.py --test       # fire a test alert immediately

The monitor tracks a high-water mark (last seen event timestamp) so it only
evaluates NEW events each cycle, never re-alerting on the same event twice.

Alert channels (configured in .env):
    ALERT_LOG=true          always-on: writes to monitor/alerts.jsonl
    ALERT_WEBHOOK_URL=      optional: POST to Slack/Teams/Discord webhook
    ALERT_EMAIL_TO=         optional: send email (requires SMTP config)
"""

import os
import sys
import json
import time
import argparse
import smtplib
import requests
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from email.mime.text import MIMEText
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

ES_HOST       = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX      = os.getenv("ES_INDEX", "sentinela-events")
INTERVAL      = int(os.getenv("MONITOR_INTERVAL", "60"))
ALERT_LOG     = os.getenv("ALERT_LOG", "true").lower() == "true"
WEBHOOK_URL   = os.getenv("ALERT_WEBHOOK_URL", "")
EMAIL_TO      = os.getenv("ALERT_EMAIL_TO", "")
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")

ALERTS_FILE   = os.path.join(os.path.dirname(__file__), "alerts.jsonl")
STATE_FILE    = os.path.join(os.path.dirname(__file__), ".monitor_state.json")

# ANSI
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"

# ─── Detection Rules ──────────────────────────────────────────────────────────
#
# Each rule is a dict with:
#   name        - short identifier
#   description - human-readable name shown in alert
#   severity    - critical / high / medium
#   check       - function(events: list[dict]) -> list[dict] of matching events
#   cooldown    - seconds before same rule can fire again (prevents spam)

def rule_threat_intel_new(events):
    """Any new event from a known-bad IP."""
    return [e for e in events if "threat_intel_match" in e.get("tags", [])]

def rule_successful_login_from_bad_ip(events):
    """Successful SSH login from a threat-intel-matched IP."""
    return [
        e for e in events
        if e.get("source_type") == "auth"
        and "Successful" in e.get("message", "")
        and "threat_intel_match" in e.get("tags", [])
    ]

def rule_brute_force_burst(events):
    """20+ failed logins from same IP within the window."""
    failures = defaultdict(list)
    for e in events:
        if "login_failure" in e.get("tags", []) and e.get("src_ip"):
            failures[e["src_ip"]].append(e)
    return [
        evts[0] for ip, evts in failures.items()
        if len(evts) >= 5  # lower threshold for monitor (full burst spans history)
    ]

def rule_internal_port_scan(events):
    """Internal host scanning other internal hosts."""
    return [
        e for e in events
        if "port_scan" in e.get("tags", [])
        or "lateral_movement" in e.get("tags", [])
    ]

def rule_ids_alert(events):
    """Any IDS alert."""
    return [e for e in events if "ids_alert" in e.get("tags", [])]

def rule_data_exfiltration(events):
    """Large outbound transfer to known-bad IP."""
    return [
        e for e in events
        if "large_transfer" in e.get("tags", [])
        and "threat_intel_match" in e.get("tags", [])
    ]

def rule_privilege_escalation(events):
    """Privilege escalation detected."""
    return [e for e in events if "privilege_escalation" in e.get("tags", [])]

RULES = [
    {
        "name":        "data_exfiltration",
        "description": "Data exfiltration to known-malicious IP",
        "severity":    "critical",
        "check":       rule_data_exfiltration,
        "cooldown":    300,
    },
    {
        "name":        "successful_login_bad_ip",
        "description": "Successful login from threat-intel-flagged IP",
        "severity":    "critical",
        "check":       rule_successful_login_from_bad_ip,
        "cooldown":    300,
    },
    {
        "name":        "internal_port_scan",
        "description": "Internal host performing port scan (possible lateral movement)",
        "severity":    "high",
        "check":       rule_internal_port_scan,
        "cooldown":    120,
    },
    {
        "name":        "ids_alert",
        "description": "IDS signature match",
        "severity":    "high",
        "check":       rule_ids_alert,
        "cooldown":    120,
    },
    {
        "name":        "privilege_escalation",
        "description": "Privilege escalation detected",
        "severity":    "high",
        "check":       rule_privilege_escalation,
        "cooldown":    120,
    },
    {
        "name":        "brute_force",
        "description": "SSH brute-force attack detected",
        "severity":    "medium",
        "check":       rule_brute_force_burst,
        "cooldown":    180,
    },
    {
        "name":        "threat_intel_hit",
        "description": "New connection from known-malicious IP",
        "severity":    "medium",
        "check":       rule_threat_intel_new,
        "cooldown":    60,
    },
]

# ─── State management ─────────────────────────────────────────────────────────

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_seen": None, "rule_last_fired": {}}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ─── Elasticsearch ────────────────────────────────────────────────────────────

def fetch_new_events(since: str | None) -> tuple[list[dict], str | None]:
    """
    Fetch events newer than `since` timestamp.
    Returns (events, latest_timestamp).
    """
    es = Elasticsearch(ES_HOST)

    if since:
        time_filter = {"range": {"timestamp": {"gt": since}}}
    else:
        # First run: look back 5 minutes to catch recent activity
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        time_filter = {"range": {"timestamp": {"gte": cutoff}}}

    try:
        result = es.search(index=ES_INDEX, body={
            "query": time_filter,
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": 500
        })
    except Exception as e:
        print(f"{RED}[ERROR] Elasticsearch query failed: {e}{RESET}")
        return [], since

    hits = result["hits"]["hits"]
    if not hits:
        return [], since

    events = [h["_source"] for h in hits]
    latest_ts = events[-1].get("timestamp")
    return events, latest_ts


# ─── Alert dispatch ───────────────────────────────────────────────────────────

def format_alert(rule: dict, matching_events: list[dict]) -> dict:
    """Build a structured alert object."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sample = matching_events[0]

    return {
        "alert_id":    f"{rule['name']}_{now}",
        "timestamp":   now,
        "rule":        rule["name"],
        "description": rule["description"],
        "severity":    rule["severity"],
        "event_count": len(matching_events),
        "sample_event": {
            "timestamp":   sample.get("timestamp"),
            "source_type": sample.get("source_type"),
            "src_ip":      sample.get("src_ip"),
            "dst_ip":      sample.get("dst_ip"),
            "dst_port":    sample.get("dst_port"),
            "message":     sample.get("message"),
            "tags":        sample.get("tags", []),
        }
    }


def dispatch_alert(alert: dict):
    """Send alert to all configured channels."""
    # Always print to console
    print_alert(alert)

    # Always write to log file
    if ALERT_LOG:
        write_alert_log(alert)

    # Optional: webhook
    if WEBHOOK_URL:
        send_webhook(alert)

    # Optional: email
    if EMAIL_TO and SMTP_HOST:
        send_email(alert)


def print_alert(alert: dict):
    sev = alert["severity"]
    color = {"critical": RED, "high": RED, "medium": YELLOW}.get(sev, CYAN)
    icon  = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "🔵")

    print(f"\n{color}{BOLD}{'='*60}{RESET}")
    print(f"{color}{BOLD}  {icon} SENTINELA ALERT — {sev.upper()}{RESET}")
    print(f"{color}{BOLD}{'='*60}{RESET}")
    print(f"  Rule:      {alert['rule']}")
    print(f"  Time:      {alert['timestamp']}")
    print(f"  Details:   {alert['description']}")
    print(f"  Events:    {alert['event_count']} matching event(s)")
    s = alert["sample_event"]
    print(f"  Sample:    {s.get('src_ip','—')} → {s.get('dst_ip','—')}:{s.get('dst_port','—')}")
    print(f"  Message:   {s.get('message','—')[:80]}")
    print(f"{color}{'='*60}{RESET}\n")


def write_alert_log(alert: dict):
    try:
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"{RED}[WARN] Could not write alert log: {e}{RESET}")


def send_webhook(alert: dict):
    """POST alert to Slack / Teams / Discord / generic webhook."""
    sev = alert["severity"]
    color_map = {"critical": "#FF4444", "high": "#F85149", "medium": "#E3B341"}
    color = color_map.get(sev, "#58C8E3")

    # Slack-compatible payload (also works for many other webhooks)
    payload = {
        "text": f"*🚨 SENTINELA ALERT — {sev.upper()}*",
        "attachments": [{
            "color": color,
            "fields": [
                {"title": "Rule",    "value": alert["rule"],        "short": True},
                {"title": "Severity","value": sev.upper(),           "short": True},
                {"title": "Details", "value": alert["description"],  "short": False},
                {"title": "Events",  "value": str(alert["event_count"]), "short": True},
                {"title": "Sample",  "value": alert["sample_event"].get("message","")[:100], "short": False},
            ],
            "footer": f"Sentinela | {alert['timestamp']}"
        }]
    }

    try:
        r = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        if r.status_code != 200:
            print(f"{YELLOW}[WARN] Webhook returned {r.status_code}{RESET}")
    except Exception as e:
        print(f"{YELLOW}[WARN] Webhook failed: {e}{RESET}")


def send_email(alert: dict):
    """
    Send a styled HTML alert email.

    WHY HTML EMAIL:
        A plain text email gets the information across but looks like
        a script output. An HTML email with color-coded severity looks
        like a product. For an IT manager receiving this in their inbox
        alongside vendor emails, presentation matters — it signals that
        Sentinela is a serious tool, not a hobby script.

        We send both HTML and plain text versions (multipart/alternative)
        so it renders correctly in all email clients, including ones that
        don't support HTML like some enterprise mail systems.
    """
    from email.mime.multipart import MIMEMultipart

    if not all([EMAIL_TO, SMTP_HOST, SMTP_USER, SMTP_PASS]):
        print(f"{YELLOW}[WARN] Email not configured — skipping{RESET}")
        return

    sev     = alert["severity"].upper()
    s       = alert["sample_event"] or {}
    ts      = alert["timestamp"].replace("T", " ").replace("Z", " UTC")
    rule    = alert["rule"]
    desc    = alert["description"]
    count   = alert["event_count"]
    src_ip  = s.get("src_ip", "—")
    dst_port= s.get("dst_port", "—")
    message = s.get("message", "—")
    tags    = ", ".join(s.get("tags", []))

    sev_colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#f85149",
        "MEDIUM":   "#e3b341",
        "LOW":      "#58c8e3",
    }
    color = sev_colors.get(sev, "#58c8e3")

    subject = f"[SENTINELA {sev}] {desc}"

    # ── HTML version ──────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#090c10;font-family:'Segoe UI',Arial,sans-serif">
  <div style="max-width:600px;margin:0 auto;padding:24px">

    <!-- Header -->
    <div style="background:#0d1117;border:1px solid #21262d;border-top:3px solid {color};border-radius:8px;padding:24px;margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
        <span style="font-family:monospace;font-size:20px;color:{color};letter-spacing:4px;font-weight:700">SENTINELA</span>
      </div>
      <div style="font-size:11px;color:#484f58;letter-spacing:2px;text-transform:uppercase">Security Operations</div>
    </div>

    <!-- Alert card -->
    <div style="background:#0d1117;border:1px solid #21262d;border-left:4px solid {color};border-radius:8px;padding:24px;margin-bottom:16px">
      <div style="margin-bottom:16px">
        <span style="background:{color}22;color:{color};border:1px solid {color}44;border-radius:3px;padding:3px 10px;font-size:11px;font-family:monospace;font-weight:700;letter-spacing:1px;text-transform:uppercase">{sev}</span>
      </div>
      <h2 style="color:#c9d1d9;font-size:18px;margin:0 0 8px">{desc}</h2>
      <div style="font-family:monospace;font-size:12px;color:#484f58">{ts}</div>
    </div>

    <!-- Details -->
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:24px;margin-bottom:16px">
      <div style="font-size:11px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#484f58;margin-bottom:16px">Event Details</div>
      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 0;color:#484f58;font-family:monospace;width:120px">Rule</td>
          <td style="padding:8px 0;color:#58c8e3;font-family:monospace">{rule}</td>
        </tr>
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 0;color:#484f58;font-family:monospace">Events</td>
          <td style="padding:8px 0;color:#e3b341;font-family:monospace">{count} matching event(s)</td>
        </tr>
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 0;color:#484f58;font-family:monospace">Source IP</td>
          <td style="padding:8px 0;color:#f85149;font-family:monospace">{src_ip}</td>
        </tr>
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 0;color:#484f58;font-family:monospace">Port</td>
          <td style="padding:8px 0;color:#c9d1d9;font-family:monospace">{dst_port}</td>
        </tr>
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 0;color:#484f58;font-family:monospace">Tags</td>
          <td style="padding:8px 0;color:#bc8cff;font-family:monospace">{tags}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#484f58;font-family:monospace;vertical-align:top">Message</td>
          <td style="padding:8px 0;color:#c9d1d9">{message}</td>
        </tr>
      </table>
    </div>

    <!-- Action button -->
    <div style="text-align:center;margin-bottom:16px">
      <a href="http://localhost:8080" style="background:#1c6679;color:#58c8e3;border:1px solid #58c8e3;border-radius:6px;padding:12px 28px;font-family:monospace;font-size:13px;font-weight:700;letter-spacing:2px;text-transform:uppercase;text-decoration:none">
        Open Dashboard →
      </a>
    </div>

    <!-- Footer -->
    <div style="text-align:center;font-size:11px;color:#484f58;font-family:monospace;letter-spacing:1px">
      SENTINELA SECURITY OPERATIONS · AUTOMATED ALERT
    </div>

  </div>
</body>
</html>"""

    # ── Plain text fallback ───────────────────────────────────────────────────
    plain = f"""SENTINELA SECURITY ALERT — {sev}
{'='*50}
{desc}
{ts}

Rule:     {rule}
Events:   {count} matching event(s)
Source:   {src_ip}:{dst_port}
Tags:     {tags}
Message:  {message}

Open dashboard: http://localhost:8080

--
Sentinela Security Operations
"""

    # ── Assemble and send ─────────────────────────────────────────────────────
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Sentinela Security <{SMTP_USER}>"
        msg["To"]      = EMAIL_TO

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html,  "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)

        print(f"{GREEN}[EMAIL] Alert sent to {EMAIL_TO}{RESET}")

    except smtplib.SMTPAuthenticationError:
        print(f"{RED}[WARN] Email auth failed — check SMTP_USER and SMTP_PASS in .env{RESET}")
        print(f"{YELLOW}        For Gmail, use an App Password, not your regular password{RESET}")
        print(f"{YELLOW}        Generate one at: myaccount.google.com → Security → App Passwords{RESET}")
    except Exception as e:
        print(f"{YELLOW}[WARN] Email failed: {e}{RESET}")


# ─── Main monitor loop ────────────────────────────────────────────────────────

def run_check(state: dict) -> dict:
    """Run one check cycle. Returns updated state."""
    now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{CYAN}[{now_str}] Checking for new events...{RESET}", end=" ", flush=True)

    events, latest_ts = fetch_new_events(state.get("last_seen"))

    if not events:
        print(f"{GREEN}No new events.{RESET}")
        return state

    print(f"{YELLOW}{len(events)} new event(s){RESET}")

    # Run each rule
    now_epoch = time.time()
    alerts_fired = 0

    for rule in RULES:
        # Check cooldown
        last_fired = state["rule_last_fired"].get(rule["name"], 0)
        if now_epoch - last_fired < rule["cooldown"]:
            continue

        matching = rule["check"](events)
        if matching:
            alert = format_alert(rule, matching)
            dispatch_alert(alert)
            state["rule_last_fired"][rule["name"]] = now_epoch
            alerts_fired += 1

    if alerts_fired == 0:
        print(f"  → {len(events)} events processed, no rules triggered.")

    if latest_ts:
        state["last_seen"] = latest_ts

    return state


def run_daemon(interval: int):
    """Main monitoring loop."""
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  SENTINELA CONTINUOUS MONITOR{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"  Elasticsearch: {ES_HOST}/{ES_INDEX}")
    print(f"  Check interval: {interval}s")
    print(f"  Alert log: {ALERTS_FILE}")
    if WEBHOOK_URL:
        print(f"  Webhook: configured")
    if EMAIL_TO:
        print(f"  Email alerts: {EMAIL_TO}")
    print(f"  Rules loaded: {len(RULES)}")
    print(f"\n  {GREEN}Monitoring started. Press Ctrl+C to stop.{RESET}\n")

    state = load_state()

    try:
        while True:
            state = run_check(state)
            save_state(state)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Monitor stopped.{RESET}")
        save_state(state)


def run_test():
    """Fire a synthetic test alert to verify all channels work."""
    print(f"\n{YELLOW}Firing test alert...{RESET}\n")
    test_alert = {
        "alert_id":    "test_alert_001",
        "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule":        "test",
        "description": "Test alert — all channels working",
        "severity":    "medium",
        "event_count": 1,
        "sample_event": {
            "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_type": "test",
            "src_ip":      "1.2.3.4",
            "dst_ip":      "192.168.1.1",
            "dst_port":    "22",
            "message":     "Test alert from Sentinela monitor",
            "tags":        ["test"],
        }
    }
    dispatch_alert(test_alert)
    print(f"{GREEN}Test complete.{RESET}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinela Continuous Monitor")
    parser.add_argument("--interval",   type=int, default=INTERVAL, help="Check interval in seconds")
    parser.add_argument("--test",        action="store_true",         help="Fire a test alert and exit")
    parser.add_argument("--test-email",  action="store_true",         help="Send a test email and exit")
    args = parser.parse_args()

    if args.test_email:
        print(f"\n{YELLOW}Sending test email to {EMAIL_TO}...{RESET}\n")
        test_alert = {
            "alert_id":    "test_email_001",
            "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rule":        "test",
            "description": "Test alert — email delivery working",
            "severity":    "medium",
            "event_count": 1,
            "sample_event": {
                "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_type": "test",
                "src_ip":      "1.2.3.4",
                "dst_ip":      "192.168.1.1",
                "dst_port":    "22",
                "message":     "Test alert from Sentinela monitor",
                "tags":        ["test"],
            }
        }
        send_email(test_alert)
        print(f"{GREEN}Done. Check your inbox at {EMAIL_TO}{RESET}\n")
        sys.exit(0)
    elif args.test:
        run_test()
    else:
        run_daemon(args.interval)