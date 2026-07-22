from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api


def split_pair(value):
    """
    Converts RouterOS values like:
        123/456
        0/0
    into two integers.
    """

    if value is None:
        return 0, 0

    value = str(value)

    if "/" not in value:
        try:
            return int(value), 0
        except:
            return 0, 0

    left, right = value.split("/", 1)

    try:
        left = int(left)
    except:
        left = 0

    try:
        right = int(right)
    except:
        right = 0

    return left, right


class QueueCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                queues = list(api(router).path("queue", "simple"))

                count = 0

                for q in queues:

                    upload_bytes, download_bytes = split_pair(q.get("bytes"))
                    upload_rate, download_rate = split_pair(q.get("rate"))
                    upload_packets, download_packets = split_pair(q.get("packets"))
                    upload_dropped, download_dropped = split_pair(q.get("dropped"))

                    db.execute(
                        """
                        INSERT INTO queue_statistics(

                            router,
                            queue_name,
                            target,
                            max_limit,

                            upload_bytes,
                            download_bytes,

                            upload_rate,
                            download_rate,

                            upload_packets,
                            download_packets,

                            upload_dropped,
                            download_dropped,

                            priority,
                            parent,
                            queue_type,
                            disabled,

                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            q.get("name"),
                            q.get("target"),
                            q.get("max-limit"),

                            upload_bytes,
                            download_bytes,

                            upload_rate,
                            download_rate,

                            upload_packets,
                            download_packets,

                            upload_dropped,
                            download_dropped,

                            q.get("priority"),
                            q.get("parent"),
                            q.get("queue"),
                            1 if q.get("disabled") else 0,

                            datetime.now().isoformat()
                        )
                    )

                    count += 1

                results.append({
                    "router": router,
                    "queues_collected": count
                })

            except Exception as e:

                results.append({
                    "router": router,
                    "error": str(e)
                })

        return results
