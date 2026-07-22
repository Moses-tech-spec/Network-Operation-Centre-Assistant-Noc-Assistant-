from pprint import pprint

from app.ai.executor import MayaExecutor

# Dry run (no execution)
pprint(
    MayaExecutor.execute("Your Router Name")
)

# Example execution (approval granted)
# pprint(
#     MayaExecutor.execute(
#         router="Your Router Name",
#         approve=True,
#         action="disconnect_pppoe",
#         target="customer_username"
#     )
# )
