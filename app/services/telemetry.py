from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api
from app.services.incident_utils import raise_incident, resolve_incidents


class TelemetryCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                resource = list(
                    api(router).path(
                        "system",
                        "resource"
                    )
                )[0]

                # Successfully reached the router — clear any open
                # "router offline" incident for it.
                resolve_incidents(router, "ROUTER_OFFLINE")

                total_memory = int(resource.get("total-memory", 0))
                free_memory = int(resource.get("free-memory", 0))

                memory_used = total_memory - free_memory

                temperature = resource.get("temperature")

                if temperature is None:
                    temperature = 0

                db.execute(
                    """
                    INSERT INTO router_health(

                        router,
                        cpu_load,
                        memory_used,
                        memory_total,
                        uptime,
                        temperature,
                        collected_at

                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        router,
                        int(resource.get("cpu-load", 0)),
                        memory_used,
                        total_memory,
                        resource.get("uptime"),
                        int(temperature),
                        datetime.now().isoformat()
                    )
                )

                results.append({

                    "router": router,

                    "cpu": int(resource.get("cpu-load", 0)),

                    "memory_used": memory_used,

                    "memory_total": total_memory,

                    "uptime": resource.get("uptime"),

                    "temperature": temperature

                })

            except Exception as e:

                raise_incident(
                    router=router,
                    category="ROUTER_OFFLINE",
                    severity="CRITICAL",
                    title="Router Unreachable",
                    description=f"Failed to connect to {router}: {str(e)}",
                )

                results.append({

                    "router": router,

                    "error": str(e)

                })

        return results
