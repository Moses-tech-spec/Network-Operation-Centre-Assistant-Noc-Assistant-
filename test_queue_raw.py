from pprint import pprint

from app.config import ROUTERS
from app.routers.mikrotik import api

for router in ROUTERS:

    print("\n==========================")
    print(router)
    print("==========================")

    try:

        queues = list(api(router).path("queue", "simple"))

        if queues:
            pprint(queues[0])
        else:
            print("No queues found.")

    except Exception as e:
        print(e)
