from app.database.database import db
from app.config import ROUTERS
from app.routers.mikrotik import api


class IncidentEngine:

    @staticmethod
    def check_router(router):

        resource = list(
            api(router).path(
                "system",
                "resource"
            )
        )[0]

        cpu_load = int(resource.get("cpu-load", 0))

        total_memory = int(resource.get("total-memory", 0))
        free_memory = int(resource.get("free-memory", 0))

        memory_used = total_memory - free_memory

        memory_percent = 0

        if total_memory > 0:
            memory_percent = round(
                (memory_used / total_memory) * 100,
                2
            )

        incidents = []

        if cpu_load >= 90:

            incidents.append({

                "severity": "CRITICAL",

                "category": "CPU",

                "title": "High CPU Usage",

                "description": f"CPU usage is {cpu_load}%"

            })

        elif cpu_load >= 75:

            incidents.append({

                "severity": "WARNING",

                "category": "CPU",

                "title": "CPU Load Rising",

                "description": f"CPU usage is {cpu_load}%"

            })

        if memory_percent >= 90:

            incidents.append({

                "severity": "CRITICAL",

                "category": "MEMORY",

                "title": "Low Memory",

                "description": f"Memory utilization is {memory_percent}%"

            })

        for incident in incidents:

            db.execute(
                """
                INSERT INTO incidents(
                    router,
                    severity,
                    category,
                    title,
                    description,
                    source
                )
                VALUES(?,?,?,?,?,?)
                """,
                (
                    router,
                    incident["severity"],
                    incident["category"],
                    incident["title"],
                    incident["description"],
                    "Incident Engine"
                )
            )

        return {

            "router": router,

            "cpu_load": cpu_load,

            "memory_percent": memory_percent,

            "incident_count": len(incidents),

            "incidents": incidents

        }

    @staticmethod
    def run():

        results = []

        for router in ROUTERS:

            try:

                results.append(
                    IncidentEngine.check_router(router)
                )

            except Exception as e:

                results.append({

                    "router": router,

                    "error": str(e)

                })

        return results

    @staticmethod
    def history(router):

        return db.fetchall(
            """
            SELECT *
            FROM incidents
            WHERE router=?
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (router,)
        )
