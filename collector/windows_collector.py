"""
Sentinela - Windows Event Log Collector
Reads real security events from the Windows Event Log and normalizes
them into the Sentinela schema for indexing into Elasticsearch.

WHY THIS EXISTS:
    The synthetic log generator was useful for building and testing the
    pipeline, but it generates fake data. This collector reads real events
    from your actual machine — every login, privilege escalation, and
    suspicious authentication attempt that Windows has recorded.

HOW IT WORKS:
    Windows stores security events in a structured log accessible via the
    Windows API. We use the `pywin32` library to subscribe to new events
    as they arrive (like tail -f but for Windows), normalize each event
    into our unified schema, and push it to Elasticsearch.

    The key design decision is event filtering: we ignore noisy, low-value
    event IDs (like 5379 credential reads) and focus on authentication and
    privilege events that actually tell a security story.

REQUIRES:
    - Run as Administrator (Windows Security log requires elevated access)
    - pip install pywin32 elasticsearch python-dotenv

USAGE:
    python collector/windows_collector.py              # run continuously
    python collector/windows_collector.py --historical # ingest last 24h first
    python collector/windows_collector.py --test       # print events, don't index
"""

import os
import sys
import uuid
import json
import time
import argparse
import re
from datetime import datetime, timezone, timedelta

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import winerror
    import pywintypes
except ImportError:
    print("[ERROR] pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

from elasticsearch import Elasticsearch
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

ES_HOST    = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX   = os.getenv("ES_INDEX", "sentinela-events")
HOST_NAME  = os.environ.get("COMPUTERNAME", "localhost")

# Event IDs we care about and why:
# 4624 - Successful logon          (who logged in, how, from where)
# 4625 - Failed logon              (brute force detection)
# 4634 - Logoff                    (session tracking)
# 4647 - User-initiated logoff     (deliberate logout vs session drop)
# 4648 - Logon with explicit creds (pass-the-hash, lateral movement indicator)
# 4672 - Special privileges        (admin/elevated access granted)
# 4688 - Process creation          (what programs are running - needs audit policy)
# 4698 - Scheduled task created    (persistence mechanism)
# 4702 - Scheduled task modified   (persistence mechanism)
# 4720 - User account created      (new accounts = potential backdoor)
# 4722 - User account enabled
# 4725 - User account disabled
# 4726 - User account deleted
# 4732 - Member added to group     (privilege escalation)
# 4756 - Member added to universal group
# 4776 - NTLM auth attempt         (credential validation)
# 4798 - User's group membership enumerated (reconnaissance)
# 4799 - Security-enabled group enumerated  (reconnaissance)

WATCHED_EVENT_IDS = {
    4624, 4625, 4634, 4647, 4648, 4672, 4688,
    4698, 4702, 4720, 4722, 4725, 4726, 4732,
    4756, 4776, 4798, 4799
}

# Event IDs we explicitly ignore because they're noisy and low-value
# 5379 - Credential Manager read (fires constantly in background)
# 5058 - Key file operation
# 5059 - Key migration operation
# 5061 - Cryptographic operation
IGNORED_EVENT_IDS = {5379, 5058, 5059, 5061}

# Logon type codes — Windows uses integers to describe HOW a login happened
# This is important for security analysis: type 3 (network) logins from
# unexpected sources are a key lateral movement indicator
LOGON_TYPES = {
    2:  "interactive",      # sitting at keyboard
    3:  "network",          # net use, file shares, remote
    4:  "batch",            # scheduled tasks
    5:  "service",          # service startup
    7:  "unlock",           # screen unlock
    8:  "network_cleartext",# cleartext password over network (bad)
    9:  "new_credentials",  # runas /netonly
    10: "remote_interactive",# RDP
    11: "cached_interactive",# cached domain credentials
}

# Known bad IPs — same list as synthetic pipeline, will grow over time
KNOWN_BAD_IPS = {
    "45.33.32.156", "185.220.101.1", "194.165.16.11", "103.75.190.1"
}

# ─── Event parsing ────────────────────────────────────────────────────────────

def extract_field(message: str, field_name: str) -> str | None:
    """
    Extract a field value from a Windows event message string.

    WHY REGEX HERE:
        Windows event messages are localized (yours are in Portuguese!)
        and the field labels change language. But the structure is consistent:
        a label followed by a colon and tabs, then the value. We extract
        by position relative to known field names in English since pywin32
        gives us the raw XML data we can also parse.

        Actually we'll parse the XML directly which is language-independent.
    """
    # Try to find value after "FieldName\t\t\tValue" pattern
    pattern = rf'{re.escape(field_name)}\s*:\s*([^\r\n]+)'
    match = re.search(pattern, message, re.IGNORECASE)
    if match:
        val = match.group(1).strip()
        return val if val and val != '-' else None
    return None


def parse_event_xml(event_handle, event_id: int) -> dict:
    """
    Parse a Windows event into a structured dict.

    WHY XML:
        Every Windows event has two representations — a human-readable
        localized Message string (which is in Portuguese on your machine)
        and a structured XML record with consistent field names regardless
        of language. We use the XML so our parser works on any Windows
        machine in any language. This is critical for a product.
    """
    try:
        # Get the formatted message (for the human-readable 'message' field)
        message = win32evtlogutil.SafeFormatMessage(event_handle, "Security")
    except Exception:
        message = f"Event ID {event_id}"

    # Extract time — Windows uses a COM timestamp, convert to UTC
    time_generated = event_handle.TimeGenerated
    try:
        ts = datetime(
            time_generated.year, time_generated.month, time_generated.day,
            time_generated.hour, time_generated.minute, time_generated.second,
            tzinfo=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get insertion strings — these are the raw field values Windows embeds
    # in events, language-independent positional data
    strings = list(event_handle.StringInserts or [])

    return {
        "ts":      ts,
        "message": message[:500] if message else f"Event {event_id}",
        "strings": strings,
        "raw":     message[:1000] if message else "",
    }


def normalize_4624(parsed: dict) -> dict:
    """Successful logon — the most common and important event."""
    strings = parsed["strings"]
    # String positions for 4624:
    # [5]  = Logon Type
    # [8]  = New Logon Account Name
    # [9]  = New Logon Domain
    # [17] = Source Network Address
    # [18] = Source Port

    logon_type_int = int(strings[8]) if len(strings) > 8 and strings[8].isdigit() else 0
    logon_type     = LOGON_TYPES.get(logon_type_int, f"type_{logon_type_int}")
    account        = strings[5] if len(strings) > 5 else None
    src_ip         = strings[18] if len(strings) > 18 else None
    src_port       = strings[19] if len(strings) > 19 else None

    # Clean up IP — Windows sometimes puts "-" or "::1" (IPv6 loopback)
    if src_ip in ("-", "::1", "127.0.0.1", None):
        src_ip = None

    tags = ["logon_success"]
    severity = "info"

    # Network logons from external IPs are more interesting than local service logons
    if logon_type_int == 3 and src_ip:
        tags.append("network_logon")
        severity = "medium"

    # RDP logons always worth flagging
    if logon_type_int == 10:
        tags.append("rdp_logon")
        severity = "medium"

    # Cleartext password over network is always bad
    if logon_type_int == 8:
        tags.append("cleartext_credentials")
        severity = "high"

    if src_ip and src_ip in KNOWN_BAD_IPS:
        tags.append("threat_intel_match")
        severity = "critical"

    return {
        "action":   f"logon_success_{logon_type}",
        "user":     account,
        "src_ip":   src_ip,
        "src_port": int(src_port) if src_port and src_port.isdigit() else None,
        "severity": severity,
        "category": "authentication",
        "tags":     tags,
        "message":  f"Successful {logon_type} login for {account or 'unknown'}" +
                    (f" from {src_ip}" if src_ip else ""),
    }


def normalize_4625(parsed: dict) -> dict:
    """Failed logon — primary brute force indicator."""
    strings = parsed["strings"]
    account    = strings[5]  if len(strings) > 5  else None
    logon_type = int(strings[10]) if len(strings) > 10 and strings[10].isdigit() else 0
    src_ip     = strings[19] if len(strings) > 19 else None
    fail_reason= strings[9]  if len(strings) > 9  else None

    if src_ip in ("-", "::1", "127.0.0.1", None):
        src_ip = None

    tags = ["login_failure"]
    severity = "medium"

    if src_ip and src_ip in KNOWN_BAD_IPS:
        tags.append("threat_intel_match")
        severity = "high"

    # Network-based failures are more suspicious than local ones
    if logon_type == 3:
        tags.append("network_logon_failure")

    return {
        "action":   "logon_failure",
        "user":     account,
        "src_ip":   src_ip,
        "severity": severity,
        "category": "authentication",
        "tags":     tags,
        "message":  f"Failed login for {account or 'unknown'}" +
                    (f" from {src_ip}" if src_ip else "") +
                    (f" (reason: {fail_reason})" if fail_reason else ""),
    }


def normalize_4672(parsed: dict) -> dict:
    """Special privileges assigned — admin rights granted at login."""
    strings  = parsed["strings"]
    account  = strings[1] if len(strings) > 1 else None
    privs    = strings[4] if len(strings) > 4 else ""

    # SYSTEM getting privileges is noise — it happens constantly
    # We only care about real user accounts getting elevated
    if account in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return None  # signal to skip this event

    tags = ["privilege_escalation"]
    severity = "medium"

    # SeDebugPrivilege is particularly dangerous — allows attaching to any process
    if "SeDebugPrivilege" in privs:
        tags.append("debug_privilege")
        severity = "high"

    return {
        "action":   "special_privileges_assigned",
        "user":     account,
        "severity": severity,
        "category": "privilege_escalation",
        "tags":     tags,
        "message":  f"Special privileges assigned to {account or 'unknown'}",
    }


def normalize_4648(parsed: dict) -> dict:
    """Explicit credential use — someone used RunAs or passed credentials."""
    strings    = parsed["strings"]
    account    = strings[5] if len(strings) > 5 else None
    target_srv = strings[9] if len(strings) > 9 else None
    src_ip     = strings[12] if len(strings) > 12 else None

    if src_ip in ("-", "::1", None):
        src_ip = None

    return {
        "action":   "explicit_credential_use",
        "user":     account,
        "src_ip":   src_ip,
        "severity": "medium",
        "category": "authentication",
        "tags":     ["explicit_credentials"],
        "message":  f"Explicit credentials used by {account or 'unknown'}" +
                    (f" targeting {target_srv}" if target_srv else ""),
    }


def normalize_4720(parsed: dict) -> dict:
    """New user account created — possible backdoor."""
    strings     = parsed["strings"]
    new_account = strings[0] if len(strings) > 0 else None
    created_by  = strings[4] if len(strings) > 4 else None

    return {
        "action":   "account_created",
        "user":     new_account,
        "severity": "high",
        "category": "account_management",
        "tags":     ["account_created"],
        "message":  f"New account created: {new_account or 'unknown'}" +
                    (f" by {created_by}" if created_by else ""),
    }


def normalize_4732(parsed: dict) -> dict:
    """Member added to security group — privilege escalation path."""
    strings    = parsed["strings"]
    member     = strings[0] if len(strings) > 0 else None
    group      = strings[2] if len(strings) > 2 else None
    changed_by = strings[6] if len(strings) > 6 else None

    severity = "high" if group and "Admin" in group else "medium"

    return {
        "action":   "group_member_added",
        "user":     member,
        "severity": severity,
        "category": "account_management",
        "tags":     ["group_change", "privilege_escalation"] if severity == "high" else ["group_change"],
        "message":  f"{member or 'unknown'} added to group {group or 'unknown'}" +
                    (f" by {changed_by}" if changed_by else ""),
    }


def normalize_4798_4799(parsed: dict, event_id: int) -> dict:
    """Group membership enumeration — reconnaissance indicator."""
    strings = parsed["strings"]
    account = strings[0] if len(strings) > 0 else None
    process = strings[3] if len(strings) > 3 else None

    return {
        "action":   "group_enumeration",
        "user":     account,
        "process":  process,
        "severity": "low",
        "category": "reconnaissance",
        "tags":     ["enumeration"],
        "message":  f"Group membership enumerated for {account or 'unknown'}" +
                    (f" by process {process}" if process else ""),
    }


# Map event IDs to their normalizer functions
NORMALIZERS = {
    4624: normalize_4624,
    4625: normalize_4625,
    4672: normalize_4672,
    4648: normalize_4648,
    4720: normalize_4720,
    4732: normalize_4732,
    4756: normalize_4732,   # same structure as 4732
    4798: lambda p: normalize_4798_4799(p, 4798),
    4799: lambda p: normalize_4798_4799(p, 4799),
}


def build_sentinela_event(event_handle, event_id: int) -> dict | None:
    """
    Convert a raw Windows event into a Sentinela normalized event.

    WHY THIS SEPARATION:
        parse_event_xml() extracts raw data from the Windows API.
        The normalizer functions interpret that data into meaning.
        build_sentinela_event() assembles the final record.

        Keeping these three steps separate means we can unit-test
        each normalizer independently and add new event types easily.
    """
    parsed = parse_event_xml(event_handle, event_id)

    # Get the appropriate normalizer, fall back to generic
    normalizer = NORMALIZERS.get(event_id)
    if normalizer:
        specific = normalizer(parsed)
        if specific is None:  # normalizer said "skip this event"
            return None
    else:
        # Generic handler for watched events without specific normalizers
        specific = {
            "action":   f"windows_event_{event_id}",
            "severity": "low",
            "category": "system",
            "tags":     [f"event_{event_id}"],
            "message":  parsed["message"][:200],
        }

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "event_id":    str(uuid.uuid4()),
        "timestamp":   parsed["ts"],
        "ingested_at": now,
        "source_type": "windows_eventlog",
        "source_host": HOST_NAME,
        "windows_event_id": event_id,
        "raw":         parsed["raw"][:500],
        **specific,
    }


# ─── Elasticsearch ────────────────────────────────────────────────────────────

def index_event(es: Elasticsearch, event: dict):
    """Index a single event into Elasticsearch."""
    try:
        es.index(index=ES_INDEX, body=event)
    except Exception as e:
        print(f"[ERROR] Failed to index event: {e}")


# ─── Historical ingestion ─────────────────────────────────────────────────────

def ingest_historical(es: Elasticsearch, hours: int = 24):
    """
    Read and index the last N hours of Security events.

    WHY HISTORICAL FIRST:
        When you first connect a real data source you want to see
        what's already there, not just wait for new events. This
        bootstraps your Elasticsearch index with real recent data
        so the AI analysis has something meaningful to work with
        immediately.
    """
    print(f"\n[collector] Ingesting last {hours}h of Windows Security events...")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    handle = win32evtlog.OpenEventLog(None, "Security")
    flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    indexed = 0
    skipped = 0
    total   = 0

    try:
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break

            for event in events:
                total += 1
                event_id = event.EventID & 0xFFFF  # mask to get clean ID

                # Stop once we've gone past our time window
                ts = event.TimeGenerated
                event_time = datetime(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, tzinfo=timezone.utc)
                if event_time < cutoff:
                    print(f"[collector] Historical: {indexed} indexed, {skipped} skipped from {total} events")
                    return indexed

                # Skip ignored and unwatched events
                if event_id in IGNORED_EVENT_IDS:
                    skipped += 1
                    continue
                if event_id not in WATCHED_EVENT_IDS:
                    skipped += 1
                    continue

                normalized = build_sentinela_event(event, event_id)
                if normalized:
                    index_event(es, normalized)
                    indexed += 1
                else:
                    skipped += 1

    finally:
        win32evtlog.CloseEventLog(handle)

    print(f"[collector] Historical: {indexed} indexed, {skipped} skipped from {total} events")
    return indexed


# ─── Real-time collection ─────────────────────────────────────────────────────

def run_realtime(es: Elasticsearch, test_mode: bool = False):
    """
    Watch for new Windows Security events in real time.

    HOW THIS WORKS:
        Windows provides a "subscription" API but for simplicity we use
        polling — check for new events every 5 seconds. We track the
        record number of the last event we processed so we never
        process the same event twice. This is the same pattern used
        by most log shippers (Filebeat, Winlogbeat, etc.).

        The trade-off: 5 second latency vs. complexity of true push
        subscription. For a security monitor, 5 seconds is fine.
    """
    print("\n[collector] Starting real-time collection (Ctrl+C to stop)...")
    print(f"[collector] Watching for event IDs: {sorted(WATCHED_EVENT_IDS)}\n")

    handle = win32evtlog.OpenEventLog(None, "Security")

    # Get current record number — we only want events from NOW forward
    total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
    last_record   = win32evtlog.GetOldestEventLogRecord(handle) + total_records - 1

    win32evtlog.CloseEventLog(handle)

    indexed = 0

    try:
        while True:
            time.sleep(5)

            # Open a fresh handle every cycle — reusing handles causes
            # "invalid handle" errors on Windows after the first read
            try:
                handle = win32evtlog.OpenEventLog(None, "Security")
            except pywintypes.error as e:
                print(f"[WARN] Could not open event log: {e}")
                continue

            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            try:
                # Read all events since last known record
                while True:
                    batch = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not batch:
                        break
                    for event in batch:
                        event_id   = event.EventID & 0xFFFF
                        record_num = event.RecordNumber

                        # Skip events we've already processed
                        if record_num <= last_record:
                            continue
                        last_record = max(last_record, record_num)

                        if event_id in IGNORED_EVENT_IDS:
                            continue
                        if event_id not in WATCHED_EVENT_IDS:
                            continue

                        normalized = build_sentinela_event(event, event_id)
                        if not normalized:
                            continue

                        if test_mode:
                            print(json.dumps(normalized, indent=2))
                        else:
                            index_event(es, normalized)
                            indexed += 1
                            sev = normalized.get("severity", "info").upper()
                            msg = normalized.get("message", "")[:70]
                            ts  = normalized.get("timestamp", "")[-8:-1]
                            print(f"[{ts}] {sev:<8} | EVT-{event_id} | {msg}")

            except pywintypes.error:
                pass
            finally:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

    except KeyboardInterrupt:
        print(f"\n[collector] Stopped. {indexed} events indexed this session.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinela Windows Event Log Collector")
    parser.add_argument("--historical", action="store_true", help="Ingest last 24h before going real-time")
    parser.add_argument("--hours",      type=int, default=24, help="Hours of history to ingest (default 24)")
    parser.add_argument("--test",       action="store_true", help="Print events to console, don't index")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  SENTINELA — Windows Event Log Collector")
    print("="*60)
    print(f"  Host:          {HOST_NAME}")
    print(f"  Elasticsearch: {ES_HOST}/{ES_INDEX}")
    print(f"  Watching:      {len(WATCHED_EVENT_IDS)} event types")
    print(f"  Ignoring:      {len(IGNORED_EVENT_IDS)} noisy event types")
    if args.test:
        print(f"  Mode:          TEST (printing only, not indexing)")
    print()

    if args.test:
        es = None
    else:
        es = Elasticsearch(ES_HOST)
        try:
            es.cluster.health()
            print(f"[collector] Elasticsearch connected OK")
        except Exception as e:
            print(f"[ERROR] Cannot connect to Elasticsearch: {e}")
            print(f"        Make sure Docker is running and ES is up.")
            sys.exit(1)

    if args.historical and not args.test:
        ingest_historical(es, hours=args.hours)

    run_realtime(es, test_mode=args.test)