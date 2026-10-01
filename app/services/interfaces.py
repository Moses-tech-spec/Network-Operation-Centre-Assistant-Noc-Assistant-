from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api
from app.services.incident_utils import raise_incident, resolve_incidents


class InterfaceCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                interfaces = list(
                    api(router).path("interface")
                )

                # Capture previous running-state AND byte counters before
                # we wipe the table, so we can detect up/down transitions
                # and compute real throughput (bytes delta / time delta).
                previous_rows = db.fetchall(
                    """
                    SELECT interface_name, running, rx_bytes, tx_bytes, collected_at
                    FROM interfaces WHERE router=?
                    """,
                    (router,)
                )
                previous_state = {
                    row["interface_name"]: row["running"] for row in previous_rows
                }
                previous_counters = {
                    row["interface_name"]: row for row in previous_rows
                }

                # Remove previous snapshot
                db.execute(
                    "DELETE FROM interfaces WHERE router=?",
                    (router,)
                )

                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS interface_traffic_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router TEXT,
                        interface_name TEXT,
                        rx_rate INTEGER,
                        tx_rate INTEGER,
                        running INTEGER,
                        collected_at TEXT
                    )
                    """
                )

                now_iso = datetime.now().isoformat()

                for interface in interfaces:

                    name = interface.get("name")
                    rx_bytes = int(interface.get("rx-byte", 0))
                    tx_bytes = int(interface.get("tx-byte", 0))

                    rx_rate = 0
                    tx_rate = 0

                    prev = previous_counters.get(name)
                    if prev:
                        try:
                            prev_time = datetime.fromisoformat(prev["collected_at"])
                            time_delta = (datetime.now() - prev_time).total_seconds()
                        except Exception:
                            time_delta = 0

                        if time_delta > 0:
                            rx_delta = rx_bytes - int(prev["rx_bytes"] or 0)
                            tx_delta = tx_bytes - int(prev["tx_bytes"] or 0)

                            # Negative delta means the counter reset (reboot)
                            # rather than a real throughput drop below zero --
                            # treat this cycle's rate as unknown (0) instead of
                            # computing a nonsensical negative value.
                            if rx_delta >= 0:
                                rx_rate = int((rx_delta * 8) / time_delta)
                            if tx_delta >= 0:
                                tx_rate = int((tx_delta * 8) / time_delta)

                    db.execute(
                        """
                        INSERT INTO interfaces(

                            router,
                            interface_name,
                            running,
                            disabled,
                            rx_bytes,
                            tx_bytes,
                            rx_packets,
                            tx_packets,
                            rx_rate,
                            tx_rate,
                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            name,
                            1 if interface.get("running") else 0,
                            1 if interface.get("disabled") else 0,
                            rx_bytes,
                            tx_bytes,
                            int(interface.get("rx-packet", 0)),
                            int(interface.get("tx-packet", 0)),
                            rx_rate,
                            tx_rate,
                            now_iso
                        )
                    )

                    db.execute(
                        """
                        INSERT INTO interface_traffic_history(
                            router, interface_name, rx_rate, tx_rate, running, collected_at
                        )
                        VALUES(?,?,?,?,?,?)
                        """,
                        (
                            router,
                            name,
                            rx_rate,
                            tx_rate,
                            1 if interface.get("running") else 0,
                            now_iso
                        )
                    )

                # Keep only the last ~20 minutes of history per router to
                # prevent unbounded growth (40 samples at 30s cadence).
                db.execute(
                    """
                    DELETE FROM interface_traffic_history
                    WHERE router=? AND collected_at < datetime('now', '-20 minutes')
                    """,
                    (router,)
                )

                for interface in interfaces:

                    name = interface.get("name")
                    disabled = bool(interface.get("disabled"))
                    running_now = 1 if interface.get("running") else 0
                    running_before = previous_state.get(name)

                    if disabled:
                        continue

                    category = f"LINK_DOWN:{name}"

                    if running_before == 1 and running_now == 0:
                        raise_incident(
                            router=router,
                            category=category,
                            severity="WARNING",
                            title=f"Interface {name} Down",
                            description=f"Interface '{name}' on {router} went down.",
                        )
                    elif running_before == 0 and running_now == 1:
                        resolve_incidents(router, category)

                results.append({

                    "router": router,
                    "interfaces": len(interfaces)

                })

            except Exception as e:

                results.append({

                    "router": router,
                    "error": str(e)

                })

        return results
