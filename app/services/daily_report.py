import os
import requests
from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import get_pppoe

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


def format_bytes(num_bytes):
    if num_bytes is None or num_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(num_bytes)
    i = 0
    while val >= 1024 and i < len(units) - 1:
        val /= 1024
        i += 1
    return f"{val:.2f} {units[i]}"


def _router_usage_last_24h(router_name):
    """
    Sums (last - first) download/upload bytes per customer queue over
    the last 24h, then totals across all queues on this router. Using
    per-customer queue totals rather than interface counters avoids
    double-counting traffic across overlapping VLANs/physical ports
    on the same uplink.
    """
    rows = db.fetchall(
        """
        SELECT queue_name, upload_bytes, download_bytes, collected_at
        FROM queue_usage_history
        WHERE router=? AND collected_at >= datetime('now', '-24 hours')
        ORDER BY queue_name, collected_at ASC
        """,
        (router_name,)
    )

    per_queue_first = {}
    per_queue_last = {}
    for r in rows:
        name = r["queue_name"]
        if name not in per_queue_first:
            per_queue_first[name] = r
        per_queue_last[name] = r

    total_down = 0
    total_up = 0
    for name in per_queue_first:
        first = per_queue_first[name]
        last = per_queue_last[name]
        down_delta = (last["download_bytes"] or 0) - (first["download_bytes"] or 0)
        up_delta = (last["upload_bytes"] or 0) - (first["upload_bytes"] or 0)
        if down_delta > 0:
            total_down += down_delta
        if up_delta > 0:
            total_up += up_delta

    return total_down, total_up


def _router_incidents_last_24h(router_name):
    rows = db.fetchall(
        """
        SELECT severity, COUNT(*) as cnt
        FROM incidents
        WHERE router=? AND created_at >= datetime('now', '-24 hours')
        GROUP BY severity
        """,
        (router_name,)
    )
    counts = {r["severity"]: r["cnt"] for r in rows}

    open_row = db.fetchone(
        "SELECT COUNT(*) as cnt FROM incidents WHERE router=? AND status='OPEN'",
        (router_name,)
    )
    open_count = open_row["cnt"] if open_row else 0

    return counts, open_count


def build_daily_report_text():
    lines = [f"*Hyperwave NOC — Daily Report*", f"_{datetime.now().strftime('%Y-%m-%d %H:%M')}_", ""]

    for router_name in ROUTERS:
        lines.append(f"*{router_name.upper()}*")

        try:
            pppoe = get_pppoe(router_name)
            active = pppoe.get("active_users", 0)
        except Exception:
            active = "unknown"

        try:
            down, up = _router_usage_last_24h(router_name)
            usage_line = f"Down {format_bytes(down)} / Up {format_bytes(up)}"
        except Exception:
            usage_line = "usage data unavailable"

        try:
            incident_counts, open_count = _router_incidents_last_24h(router_name)
            critical_count = incident_counts.get("CRITICAL", 0)
            warning_count = incident_counts.get("WARNING", 0)
            incident_line = f"{open_count} open now | +{critical_count} critical / +{warning_count} warning (24h)"
        except Exception:
            incident_line = "incident data unavailable"

        lines.append(f"  Active customers: {active}")
        lines.append(f"  24h usage: {usage_line}")
        lines.append(f"  Incidents: {incident_line}")
        lines.append("")

    return "\n".join(lines)


def send_telegram_message(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"success": False, "message": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured."}

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "Markdown"
            },
            timeout=15
        )
        resp.raise_for_status()
        return {"success": True}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": str(e)}


def send_daily_report():
    text = build_daily_report_text()
    result = send_telegram_message(text)
    if result.get("success"):
        print("Daily report sent to Telegram successfully.")
    else:
        print(f"Daily report FAILED to send: {result.get('message')}")
    return result
