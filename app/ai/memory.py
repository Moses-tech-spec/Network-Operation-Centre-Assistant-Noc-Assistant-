from app.database.database import db


class MayaMemory:
    """
    Builds a complete network context for Maya.

    Every diagnosis and AI response should start here.
    """

    @staticmethod
    def build(router: str):

        inventory = db.fetchone(
            """
            SELECT *
            FROM router_inventory
            WHERE router=?
            ORDER BY collected_at DESC
            LIMIT 1
            """,
            (router,)
        )

        health = db.fetchone(
            """
            SELECT *
            FROM router_health
            WHERE router=?
            ORDER BY collected_at DESC
            LIMIT 1
            """,
            (router,)
        )

        interfaces = db.fetchall(
            """
            SELECT *
            FROM interfaces
            WHERE router=?
            ORDER BY collected_at DESC
            """,
            (router,)
        )

        pppoe = db.fetchall(
            """
            SELECT *
            FROM pppoe_sessions
            WHERE router=?
            ORDER BY collected_at DESC
            """,
            (router,)
        )

        incidents = db.fetchall(
            """
            SELECT *
            FROM incidents
            WHERE router=?
            AND status='OPEN'
            ORDER BY created_at DESC
            """,
            (router,)
        )

        return {

            "router": router,

            "inventory": inventory,

            "health": health,

            "interfaces": interfaces,

            "pppoe_sessions": pppoe,

            "incidents": incidents,

            "summary": {

                "interface_count": len(interfaces),

                "active_pppoe": len(pppoe),

                "open_incidents": len(incidents)

            }

        }

    @staticmethod
    def all_routers():

        routers = db.fetchall(
            """
            SELECT DISTINCT router
            FROM router_inventory
            ORDER BY router
            """
        )

        results = []

        for router in routers:

            results.append(
                MayaMemory.build(router["router"])
            )

        return results


    @staticmethod
    def search_last_seen(query):
        """
        Searches the persistent last-seen table for a customer,
        even if they are currently offline (not in live pppoe_sessions).
        """

        return db.fetchall(
            """
            SELECT *
            FROM customer_last_seen
            WHERE username LIKE ?
            ORDER BY last_seen_at DESC
            LIMIT 5
            """,
            (f"%{query}%",)
        )
