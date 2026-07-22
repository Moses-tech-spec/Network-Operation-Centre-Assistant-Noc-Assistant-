from pprint import pprint

from app.config import ROUTERS
from app.routers.mikrotik import api

for router in ROUTERS:

    print("\n========================")
    print(router)
    print("========================")

    try:

        routes = list(
            api(router).path(
                "routing",
                "route"
            )
        )

        print("Total routes:", len(routes))

        if routes:
            pprint(routes[0])

    except Exception as e:
        print(e)
