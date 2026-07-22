from app.database.database import db


class MayaContext:

    """
    Builds a complete context for one router.

    Every AI feature (Diagnosis, Chat, OpenAI)
    will use this class.
    """

    @staticmethod
    def router(router_name: str):

        inventory = db.fetchone(
            """
            SELECT *
            FROM router_inventory
            WHERE router=?
            ORDER BY collected_at DESC
            LIMIT 1
            """,
            (router_name,)
        )

        telemetry = db.fetchone(
            """
            SELECT *
            FROM router_health
            WHERE router=?
            ORDER BY collected_at DESC
            LIMIT 1
            """,
            (router_name,)
        )

        interfaces = db.fetchall(
            """
            SELECT *
            FROM interfaces
            WHERE router=?
            ORDER BY collected_at DESC
            """,
            (router_name,)
        )

        pppoe = db.fetchall(
            """
            SELECT *
            FROM pppoe_sessions
            WHERE router=?
            ORDER BY collected_at DESC
            """,
            (router_name,)
        )

        # Only the MOST RECENT snapshot per queue — not full history.
        # (Historical accumulation here was previously ballooning prompt
        # size to 20,000+ tokens and causing every AI request to time out.)
        queues = db.fetchall(
            """
            SELECT qs.*
            FROM queue_statistics qs
            INNER JOIN (
                SELECT queue_name, MAX(collected_at) AS max_collected
                FROM queue_statistics
                WHERE router=?
                GROUP BY queue_name
            ) latest
            ON qs.queue_name = latest.queue_name
            AND qs.collected_at = latest.max_collected
            WHERE qs.router=?
            ORDER BY qs.collected_at DESC
            LIMIT 50
            """,
            (router_name, router_name)
        )

        incidents = db.fetchall(
            """
            SELECT *
            FROM incidents
            WHERE router=?
            AND status='OPEN'
            ORDER BY created_at DESC
            """,
            (router_name,)
        )

        return {

            "router": router_name,

            "inventory": inventory,

            "telemetry": telemetry,

            "interfaces": interfaces,

            "pppoe_sessions": pppoe,

            "incidents": incidents,
            "queues": queues

        }

    @staticmethod
    def network():

        routers = db.fetchall(
            """
            SELECT DISTINCT router
            FROM router_inventory
            """
        )

        context = []

        for router in routers:

            context.append(

                MayaContext.router(router["router"])

            )

        return context
