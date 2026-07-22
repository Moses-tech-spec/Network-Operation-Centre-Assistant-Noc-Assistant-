from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api
from app.services.incident_utils import log_point_event


class PPPoECollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                sessions = list(
                    api(router).path(
                        "ppp",
                        "active"
                    )
                )

                # Capture who was online last cycle, before we wipe the table,
                # so we can detect who dropped between polls.
                previous_rows = db.fetchall(
                    "SELECT DISTINCT username FROM pppoe_sessions WHERE router=?",
                    (router,)
                )
                previous_usernames = {
                    row["username"] for row in previous_rows if row.get("username")
                }

                current_usernames = {
                    s.get("name") for s in sessions if s.get("name")
                }

                dropped = previous_usernames - current_usernames

                for username in dropped:
                    log_point_event(
                        router=router,
                        category="PPP_FAILURE",
                        severity="WARNING",
                        title="PPPoE Session Dropped",
                        description=f"Customer '{username}' disconnected from {router}.",
                    )

                db.execute(
                    "DELETE FROM pppoe_sessions WHERE router=?",
                    (router,)
                )

                for session in sessions:

                    db.execute(
                        """
                        INSERT INTO pppoe_sessions(

                            router,
                            username,
                            address,
                            caller_id,
                            uptime,
                            service,
                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            session.get("name"),
                            session.get("address"),
                            session.get("caller-id"),
                            session.get("uptime"),
                            session.get("service"),
                            datetime.now().isoformat()
                        )
                    )

                    # Persistent last-seen record — upsert, never deleted.
                    # This survives even after the customer disconnects,
                    # since pppoe_sessions above gets wiped every cycle.
                    db.execute(
                        """
                        INSERT INTO customer_last_seen(
                            router, username, last_ip, last_uptime, last_seen_at
                        )
                        VALUES(?,?,?,?,?)
                        ON CONFLICT(router, username) DO UPDATE SET
                            last_ip=excluded.last_ip,
                            last_uptime=excluded.last_uptime,
                            last_seen_at=excluded.last_seen_at
                        """,
                        (
                            router,
                            session.get("name"),
                            session.get("address"),
                            session.get("uptime"),
                            datetime.now().isoformat()
                        )
                    )

                results.append({

                    "router": router,

                    "sessions": len(sessions)

                })

            except Exception as e:

                results.append({

                    "router": router,

                    "error": str(e)

                })

        return results
