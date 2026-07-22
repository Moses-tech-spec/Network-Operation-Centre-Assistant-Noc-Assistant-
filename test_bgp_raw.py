from pprint import pprint

from app.config import ROUTERS
from app.routers.mikrotik import api

for router in ROUTERS:

    print("\n========================")
    print(router)
    print("========================")

    try:

        peers = list(api(router).path("routing", "bgp", "connection"))

        if peers:
            pprint(peers[0])
        else:
            print("No BGP peers found.")

    except Exception as e:
        print(e)
