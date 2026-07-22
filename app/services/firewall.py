from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api


class FirewallCollector:

    """
    Collects MikroTik firewall filter rule statistics
    and stores them in SQLite.
    """

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                # Remove old firewall statistics
                db.execute(
                    """
                    DELETE FROM firewall_rules
                    WHERE router=?
                    """,
                    (router,)
                )

                firewall = api(router)

                count = 0

                for rule in firewall.path(
                    "ip",
                    "firewall",
                    "filter"
                ):

                    packets = rule.get("packets", 0)
                    bytes_count = rule.get("bytes", 0)

                    try:
                        packets = int(packets)
                    except Exception:
                        packets = 0

                    try:
                        bytes_count = int(bytes_count)
                    except Exception:
                        bytes_count = 0

                    disabled = rule.get("disabled", False)

                    if isinstance(disabled, bool):
                        disabled = int(disabled)
                    else:
                        disabled = 1 if str(disabled).lower() == "true" else 0

                    db.execute(
                        """
                        INSERT INTO firewall_rules(

                            router,

                            chain_name,

                            action,

                            comment,

                            packets,

                            bytes,

                            disabled,

                            collected_at

                        )

                        VALUES(?,?,?,?,?,?,?,?)

                        """,
                        (
                            router,
                            rule.get("chain"),
                            rule.get("action"),
                            rule.get("comment", ""),
                            packets,
                            bytes_count,
                            disabled,
                            datetime.now().isoformat()
                        )
                    )

                    count += 1

                results.append({

                    "router": router,

                    "rules": count

                })

            except Exception as e:

                results.append({

                    "router": router,

                    "error": str(e)

                })

        return results
