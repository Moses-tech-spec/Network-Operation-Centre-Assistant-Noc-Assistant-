from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import get_path

RETENTION_DAYS = 30


def _split_pair(value, cast=int):
    try:
        a, b = str(value).split("/")
        return cast(a), cast(b)
    except Exception:
        return 0, 0


class LinkUsageCollector:
    """
    Samples the *already-collected* interface rates/bytes (written every
    30s by InterfaceCollector into the 'interfaces' table) into a
    separate, long-retention table every 5 minutes. Does not touch
    the interfaces table or the 20-minute anomaly-detection history.
    """

    @staticmethod
    def collect():
        results = []
        now_iso = datetime.now().isoformat()

        for router in ROUTERS:
            try:
                rows = db.fetchall(
                    """
                    SELECT interface_name, rx_rate, tx_rate, rx_bytes, tx_bytes
                    FROM interfaces WHERE router=?
                    """,
                    (router,)
                )

                for row in rows:
                    name = row.get("interface_name")
                    if not name or name.startswith("<pppoe-"):
                        continue

                    db.execute(
                        """
                        INSERT INTO link_usage_history(
                            router, interface_name, rx_rate, tx_rate,
                            rx_bytes, tx_bytes, collected_at
                        )
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            router, name,
                            row.get("rx_rate") or 0, row.get("tx_rate") or 0,
                            row.get("rx_bytes") or 0, row.get("tx_bytes") or 0,
                            now_iso
                        )
                    )

                db.execute(
                    f"""
                    DELETE FROM link_usage_history
                    WHERE router=? AND collected_at < datetime('now', '-{RETENTION_DAYS} days')
                    """,
                    (router,)
                )

                results.append({"router": router, "status": "ok"})

            except Exception as e:
                results.append({"router": router, "error": str(e)})

        return results


class QueueUsageCollector:
    """
    Polls each router's simple queues directly (not derived from
    another table, since nothing else currently tracks per-customer
    traffic) and stores upload/download rate + cumulative bytes.
    RouterOS reports 'rate' as a live bps value already, so no
    delta math is needed here (unlike interface rx/tx rates).
    """

    @staticmethod
    def collect():
        results = []
        now_iso = datetime.now().isoformat()

        for router in ROUTERS:
            try:
                queues = get_path(router, "queue", "simple")

                for q in queues:
                    up_bytes, down_bytes = _split_pair(q.get("bytes", "0/0"))
                    up_rate, down_rate = _split_pair(q.get("rate", "0/0"))

                    db.execute(
                        """
                        INSERT INTO queue_usage_history(
                            router, queue_name, target, upload_rate, download_rate,
                            upload_bytes, download_bytes, disabled, collected_at
                        )
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            q.get("name"),
                            q.get("target"),
                            up_rate, down_rate,
                            up_bytes, down_bytes,
                            1 if str(q.get("disabled")).lower() == "true" else 0,
                            now_iso
                        )
                    )

                db.execute(
                    f"""
                    DELETE FROM queue_usage_history
                    WHERE router=? AND collected_at < datetime('now', '-{RETENTION_DAYS} days')
                    """,
                    (router,)
                )

                results.append({"router": router, "queues": len(queues)})

            except Exception as e:
                results.append({"router": router, "error": str(e)})

        return results
