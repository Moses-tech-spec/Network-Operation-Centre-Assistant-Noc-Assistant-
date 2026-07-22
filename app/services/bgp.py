from datetime import datetime

from app.config import ROUTERS
from app.database.database import db
from app.routers.mikrotik import api


class BGPCollector:

    @staticmethod
    def collect():

        results = []

        for router in ROUTERS:

            try:

                peers = list(
                    api(router).path(
                        "routing",
                        "bgp",
                        "connection"
                    )
                )

                count = 0

                for peer in peers:

                    state = (
                        "INACTIVE"
                        if peer.get("inactive")
                        else "ACTIVE"
                    )

                    db.execute(
                        """
                        INSERT INTO bgp_peers(

                            router,
                            peer_name,
                            remote_address,
                            remote_as,
                            state,
                            uptime,
                            prefixes_received,
                            prefixes_advertised,
                            collected_at

                        )
                        VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            router,
                            peer.get("name"),
                            peer.get("remote.address"),
                            str(peer.get("remote.as")),
                            state,
                            "",
                            0,
                            0,
                            datetime.now().isoformat()
                        )
                    )

                    count += 1

                results.append({
                    "router": router,
                    "bgp_peers": count
                })

            except Exception as e:

                results.append({
                    "router": router,
                    "error": str(e)
                })

        return results
