from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api


class RouteCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                routes = list(
                    api(router).path(
                        "routing",
                        "route"
                    )
                )

                # Remove previous snapshot

                db.execute(

                    "DELETE FROM routing_table WHERE router=?",

                    (router,)

                )

                rows = []

                timestamp = datetime.now().isoformat()

                for route in routes:

                    rows.append(

                        (

                            router,

                            route.get("dst-address", ""),

                            route.get("gateway", ""),

                            int(route.get("distance", 0)),

                            route.get("routing-table", "main"),

                            route.get("belongs-to", "unknown"),

                            0 if route.get("unreachable") else 1,

                            1 if route.get("disabled") else 0,

                            timestamp

                        )

                    )

                db.executemany(

                    """

                    INSERT INTO routing_table(

                        router,

                        destination,

                        gateway,

                        distance,

                        routing_table,

                        route_type,

                        active,

                        disabled,

                        collected_at

                    )

                    VALUES(?,?,?,?,?,?,?,?,?)

                    """,

                    rows

                )

                results.append({

                    "router": router,

                    "routes": len(rows)

                })

            except Exception as e:

                results.append({

                    "router": router,

                    "error": str(e)

                })

        return results
