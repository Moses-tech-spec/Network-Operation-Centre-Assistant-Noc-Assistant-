from pprint import pprint

from app.config import ROUTERS
from app.routers.mikrotik import api

for router in ROUTERS:

    print("\n======================")
    print(router)
    print("======================")

    try:

        neighbors = list(
            api(router).path(
                "routing",
                "ospf",
                "neighbor"
            )
        )

        if neighbors:
            pprint(neighbors[0])
        else:
            print("No OSPF neighbors.")

    except Exception as e:
        print(e)
