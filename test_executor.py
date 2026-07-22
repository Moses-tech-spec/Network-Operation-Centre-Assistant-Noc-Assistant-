from pprint import pprint

from app.ai.executor import MayaExecutor

# Dry run (no execution)
pprint(
    MayaExecutor.execute("kincar")
)

# Example execution (approval granted)
# pprint(
#     MayaExecutor.execute(
#         router="kincar",
#         approve=True,
#         action="disconnect_pppoe",
#         target="customer_username"
#     )
# )
