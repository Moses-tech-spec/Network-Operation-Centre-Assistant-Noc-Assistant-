from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api


class OSPFCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                neighbors = list(
                    api(router).path(
                        "routing",
                        "ospf",
                        "neighbor"
                    )
                )

                count = 0

                for n in neighbors:

                    db.execute(
                        """
                        INSERT INTO ospf_neighbors(

                            router,
                            neighbor_id,
                            address,
                            state,
                            interface,
                            priority,
                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            n.get("router-id", ""),
                            n.get("address", ""),
                            n.get("state", ""),
                            n.get("interface", ""),
                            int(n.get("priority", 0)),
                            datetime.now().isoformat()
                        )
                    )

                    count += 1

                results.append({
                    "router": router,
                    "ospf_neighbors": count
                })

            except Exception as e:

                results.append({
                    "router": router,
                    "error": str(e)
                })

        return results
