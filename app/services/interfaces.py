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

                for interface in interfaces:

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
                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            interface.get("name"),
                            1 if interface.get("running") else 0,
                            1 if interface.get("disabled") else 0,
                            int(interface.get("rx-byte", 0)),
                            int(interface.get("tx-byte", 0)),
                            int(interface.get("rx-packet", 0)),
                            int(interface.get("tx-packet", 0)),
                            datetime.now().isoformat()
                        )
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
