from app.config import ROUTERS
from app.database.database import db
from app.services.incident_utils import raise_incident, resolve_incidents

ZERO_CONSECUTIVE_CYCLES = 3
ZERO_LOOKBACK_SAMPLES = 10
ZERO_ACTIVITY_THRESHOLD_BPS = 100_000

BASELINE_WINDOW_SAMPLES = 10
BASELINE_MIN_SAMPLES = 5
MIN_BASELINE_BPS = 500_000
SPIKE_MULTIPLIER = 3.0


def _get_recent_samples(router, interface_name, limit):
    return db.fetchall(
        """
        SELECT rx_rate, tx_rate, running, collected_at
        FROM interface_traffic_history
        WHERE router=? AND interface_name=?
        ORDER BY collected_at DESC
        LIMIT ?
        """,
        (router, interface_name, limit)
    )


def _distinct_interfaces(router):
    rows = db.fetchall(
        "SELECT DISTINCT interface_name FROM interface_traffic_history WHERE router=?",
        (router,)
    )
    names = [r["interface_name"] for r in rows if r.get("interface_name")]
    # Physical/uplink interfaces only -- per-customer PPPoE instability is
    # already covered by flapping detection, and including 200+ per-customer
    # interfaces here multiplies DB load without adding distinct signal.
    return [n for n in names if not n.startswith("<pppoe-")]


def _check_zero_traffic(router, interface_name):
    category = f"TRAFFIC_ZERO:{interface_name}"
    samples = _get_recent_samples(router, interface_name, ZERO_LOOKBACK_SAMPLES)

    if len(samples) < ZERO_CONSECUTIVE_CYCLES:
        return {"status": "insufficient_data"}

    recent = samples[:ZERO_CONSECUTIVE_CYCLES]

    all_running = all(s.get("running") == 1 for s in recent)
    all_zero = all((s.get("rx_rate") or 0) == 0 and (s.get("tx_rate") or 0) == 0 for s in recent)

    if not (all_running and all_zero):
        resolve_incidents(router, category)
        return {"status": "active"}

    had_prior_activity = any(
        (s.get("rx_rate") or 0) > ZERO_ACTIVITY_THRESHOLD_BPS or (s.get("tx_rate") or 0) > ZERO_ACTIVITY_THRESHOLD_BPS
        for s in samples
    )

    if not had_prior_activity:
        return {"status": "idle_by_default"}

    raise_incident(
        router=router,
        category=category,
        severity="WARNING",
        title=f"Interface {interface_name} has gone silent",
        description=(
            f"Interface '{interface_name}' on {router} is still reporting as "
            f"running, but has shown zero throughput for the last "
            f"{ZERO_CONSECUTIVE_CYCLES} polling cycles despite normally "
            f"carrying traffic. This can indicate an upstream failure, "
            f"blackholed route, or a link that's up but not actually passing "
            f"data — distinct from a simple link-down event."
        ),
        source="Traffic Anomaly Detection"
    )
    return {"status": "silent"}


def _check_spike(router, interface_name):
    category = f"TRAFFIC_SPIKE:{interface_name}"
    samples = _get_recent_samples(router, interface_name, BASELINE_WINDOW_SAMPLES + 1)

    if len(samples) < BASELINE_MIN_SAMPLES + 1:
        return {"status": "insufficient_data"}

    current = samples[0]
    baseline_samples = samples[1:]

    baseline_rx = sum(s.get("rx_rate") or 0 for s in baseline_samples) / len(baseline_samples)
    baseline_tx = sum(s.get("tx_rate") or 0 for s in baseline_samples) / len(baseline_samples)

    current_rx = current.get("rx_rate") or 0
    current_tx = current.get("tx_rate") or 0

    spiking_direction = None
    if baseline_rx >= MIN_BASELINE_BPS and current_rx > baseline_rx * SPIKE_MULTIPLIER:
        spiking_direction = "download (rx)"
        ratio = current_rx / baseline_rx
    elif baseline_tx >= MIN_BASELINE_BPS and current_tx > baseline_tx * SPIKE_MULTIPLIER:
        spiking_direction = "upload (tx)"
        ratio = current_tx / baseline_tx
    else:
        resolve_incidents(router, category)
        return {"status": "normal"}

    raise_incident(
        router=router,
        category=category,
        severity="WARNING",
        title=f"Traffic spike on {interface_name}",
        description=(
            f"Interface '{interface_name}' on {router} is currently at "
            f"{ratio:.1f}x its recent baseline {spiking_direction} throughput "
            f"(baseline rx {int(baseline_rx/1000)} kbps / tx {int(baseline_tx/1000)} kbps, "
            f"current rx {int(current_rx/1000)} kbps / tx {int(current_tx/1000)} kbps). "
            f"This could indicate a large transfer, DDoS/flood traffic, or a "
            f"misbehaving device on this link — review before assuming it's "
            f"benign."
        ),
        source="Traffic Anomaly Detection"
    )
    return {"status": "spiking", "direction": spiking_direction, "ratio": round(ratio, 1)}


def detect_traffic_anomalies():
    results = []
    for router in ROUTERS:
        try:
            interface_results = []
            for interface_name in _distinct_interfaces(router):
                interface_results.append({
                    "interface": interface_name,
                    "zero_traffic": _check_zero_traffic(router, interface_name),
                    "spike": _check_spike(router, interface_name),
                })
            results.append({"router": router, "interfaces": interface_results})
        except Exception as e:
            results.append({"router": router, "error": str(e)})
    return results
