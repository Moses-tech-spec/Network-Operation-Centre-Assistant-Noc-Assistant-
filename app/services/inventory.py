from datetime import datetime

from app.config import ROUTERS
from app.routers.mikrotik import (
    get_system_resource,
    api,
)

from app.database.database import db


class InventoryCollector:
    """
    Collects hardware and software inventory
    from every MikroTik router.
    """

    @staticmethod
    def collect():

        inventory = []

        for router in ROUTERS:

            try:

                system = get_system_resource(router)

                rb = list(
                    api(router).path(
                        "system",
                        "routerboard"
                    )
                )[0]

                record = {

                    "router": router,

                    "identity": system["system"]["identity"],

                    "model": rb.get("model"),

                    "board_name": rb.get("board-name"),

                    "version": system["system"]["version"],

                    "serial": rb.get("serial-number"),

                    "cpu": system["system"]["cpu"]["load"],

                    "cpu_count": system["system"]["cpu"]["count"],

                    "free_memory": system["system"]["memory"]["free_mb"],

                    "total_memory": system["system"]["memory"]["total_mb"],

                    "free_hdd": system["system"]["storage"]["free_mb"],

                    "total_hdd": system["system"]["storage"]["total_mb"],

                    "uptime": system["system"]["uptime"],

                    "architecture": system["system"]["architecture"],

                }

                db.execute(

                    """

                    INSERT INTO router_inventory(

                        router,

                        identity,

                        model,

                        board_name,

                        version,

                        serial,

                        cpu,

                        cpu_count,

                        free_memory,

                        total_memory,

                        free_hdd,

                        total_hdd,

                        uptime,

                        architecture

                    )

                    VALUES(

                        ?,?,?,?,?,?,?,?,?,?,?,?,?,?

                    )

                    """,

                    (

                        record["router"],

                        record["identity"],

                        record["model"],

                        record["board_name"],

                        record["version"],

                        record["serial"],

                        record["cpu"],

                        record["cpu_count"],

                        record["free_memory"],

                        record["total_memory"],

                        record["free_hdd"],

                        record["total_hdd"],

                        record["uptime"],

                        record["architecture"],

                    )

                )

                record["collected_at"] = datetime.utcnow().isoformat()

                inventory.append(record)

            except Exception as e:

                inventory.append({

                    "router": router,

                    "error": str(e),

                })

        return inventory

    @staticmethod
    def collect_router(router):

        if router not in ROUTERS:

            raise Exception("Router not found.")

        for item in InventoryCollector.collect():

            if item["router"] == router:

                return item
