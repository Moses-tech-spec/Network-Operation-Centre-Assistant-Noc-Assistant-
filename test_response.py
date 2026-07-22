from pprint import pprint

from app.core.response import APIResponse

pprint(

    APIResponse.success(

        data={"cpu": 15},

        router="kincar"

    )

)

print()

pprint(

    APIResponse.error(

        "Router unreachable",

        router="kincar"

    )

)
