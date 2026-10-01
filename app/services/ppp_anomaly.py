import re
from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.services.incident_utils import raise_incident, resolve_incidents

FLAP_WARNING_THRESHOLD = 3
FLAP_CRITICAL_THRESHOLD = 6
FLAP_WINDOW_MINUTES = 10

MASS_DISCONNECT_THRESHOLD = 5
MASS_DISCONNECT_WINDOW_MINUTES = 5

USERNAME_PATTERN = re.compile(r"Customer '([^']+)'")


def _get_recent_ppp_failures(router, window_minutes):
    """
    Returns a list of (username, created_at) for PPP_FAILURE point-events
    on this router within the window. Username is parsed from the
    description text logged by PPPoECollector, since it isn't stored
    in its own column (same fragility noted in get_flap_count).
    """
    rows = db.fetchall(
        """
        SELECT description, created_at FROM incidents
        WHERE router=? AND category='PPP_FAILURE'
          AND created_at >= datetime('now', ?)
        """,
        (router, f"-{window_minutes} minutes")
    )

    failures = []
    for row in rows:
        match = USERNAME_PATTERN.search(row.get("description") or "")
        if match:
            failures.append((match.group(1), row.get("created_at")))

    return failures


def _check_flapping(router):
    results = []
    failures = _get_recent_ppp_failures(router, FLAP_WINDOW_MINUTES)

    counts = {}
    for username, _ in failures:
        counts[username] = counts.get(username, 0) + 1

    for username, count in counts.items():
        category = f"PPP_FLAPPING:{username}"

        if count >= FLAP_WARNING_THRESHOLD:
            severity = "CRITICAL" if count >= FLAP_CRITICAL_THRESHOLD else "WARNING"
            raise_incident(
                router=router,
                category=category,
                severity=severity,
                title=f"Customer '{username}' is flapping",
                description=(
                    f"'{username}' has dropped and reconnected {count} times in "
                    f"the last {FLAP_WINDOW_MINUTES} minutes on {router}. This "
                    f"indicates an unstable connection rather than a single outage "
                    f"— check signal strength, physical cabling, or CPE health "
                    f"rather than treating this as a one-off drop."
                ),
                source="PPP Anomaly Detection"
            )
            results.append({"username": username, "status": "flapping", "count": count, "severity": severity})
        else:
            resolve_incidents(router, category)

    return results


def _check_mass_disconnect(router):
    category = "PPP_MASS_DISCONNECT"
    failures = _get_recent_ppp_failures(router, MASS_DISCONNECT_WINDOW_MINUTES)

    distinct_customers = {username for username, _ in failures}

    if len(distinct_customers) >= MASS_DISCONNECT_THRESHOLD:
        raise_incident(
            router=router,
            category=category,
            severity="CRITICAL",
            title=f"Mass PPPoE disconnect on {router}",
            description=(
                f"{len(distinct_customers)} distinct customers disconnected from "
                f"{router} in the last {MASS_DISCONNECT_WINDOW_MINUTES} minutes: "
                f"{', '.join(sorted(distinct_customers))}. This pattern points to "
                f"a shared cause — RADIUS/PPPoE service instability, an upstream "
                f"link issue, or the router itself — rather than isolated customer "
                f"problems. Investigate before treating individual reports as "
                f"unrelated."
            ),
            source="PPP Anomaly Detection"
        )
        return {"status": "mass_disconnect", "distinct_customers": len(distinct_customers)}

    resolve_incidents(router, category)
    return {"status": "normal", "distinct_customers": len(distinct_customers)}


def detect_ppp_anomalies():
    results = []
    for router in ROUTERS:
        try:
            results.append({
                "router": router,
                "flapping": _check_flapping(router),
                "mass_disconnect": _check_mass_disconnect(router),
            })
        except Exception as e:
            results.append({"router": router, "error": str(e)})
    return results
