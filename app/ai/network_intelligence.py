from app.database.database import db


class NetworkIntelligence:

    @staticmethod
    def collect(router):

        return {

            "health": db.fetchone(
                """
                SELECT *
                FROM router_health
                WHERE router=?
                ORDER BY collected_at DESC
                LIMIT 1
                """,
                (router,)
            ),

            "interfaces": db.fetchall(
                """
                SELECT *
                FROM interfaces
                WHERE router=?
                """,
                (router,)
            ),

            "queues": db.fetchall(
                """
                SELECT *
                FROM queue_statistics
                WHERE router=?
                """,
                (router,)
            ),

            "bgp": db.fetchall(
                """
                SELECT *
                FROM bgp_peers
                WHERE router=?
                """,
                (router,)
            ),

            "ospf": db.fetchall(
                """
                SELECT *
                FROM ospf_neighbors
                WHERE router=?
                """,
                (router,)
            ),

            "routes": db.fetchall(
                """
                SELECT *
                FROM routing_table
                WHERE router=?
                """,
                (router,)
            ),

            "firewall": db.fetchall(
                """
                SELECT *
                FROM firewall_rules
                WHERE router=?
                """,
                (router,)
            ),

            "pppoe": db.fetchall(
                """
                SELECT *
                FROM pppoe_sessions
                WHERE router=?
                """,
                (router,)
            ),

            "incidents": db.fetchall(
                """
                SELECT *
                FROM incidents
                WHERE router=?
                AND status='OPEN'
                """,
                (router,)
            )

        }
