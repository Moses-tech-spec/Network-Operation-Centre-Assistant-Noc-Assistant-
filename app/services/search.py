import concurrent.futures

from app.config import ROUTERS
from app.routers.mikrotik import get_router_connection


SEARCH_PATHS = [
    ("ppp", "secret"),
    ("ppp", "active"),
    ("ip", "dhcp-server", "lease"),
    ("ip", "arp"),
    ("queue", "simple"),
]

PER_ROUTER_TIMEOUT_SECONDS = 8


def _search_single_router(router_name, query):
    """
    Searches one router. Runs in its own thread so a hang on this
    router can be abandoned via timeout without blocking the others.
    """

    router_results = []

    try:
        api = get_router_connection(router_name)

        for path in SEARCH_PATHS:
            try:
                for item in api.path(*path):
                    values = " ".join(
                        str(v).lower()
                        for v in item.values()
                    )
                    if query in values:
                        router_results.append({
                            "router": router_name,
                            "category": "/".join(path),
                            "data": dict(item)
                        })
            except Exception:
                pass

    except Exception as e:
        return {"router": router_name, "error": str(e)}, router_results

    return None, router_results


class UniversalSearch:

    @staticmethod
    def search(query: str):

        query = query.lower()
        results = []
        errors = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ROUTERS) or 1) as executor:

            future_to_router = {
                executor.submit(_search_single_router, router_name, query): router_name
                for router_name in ROUTERS
            }

            for future in concurrent.futures.as_completed(future_to_router, timeout=None):

                router_name = future_to_router[future]

                try:
                    error, router_results = future.result(timeout=PER_ROUTER_TIMEOUT_SECONDS)

                    if error:
                        errors.append(error)
                    else:
                        results.extend(router_results)

                except concurrent.futures.TimeoutError:
                    errors.append({
                        "router": router_name,
                        "error": f"Timed out after {PER_ROUTER_TIMEOUT_SECONDS}s — router did not respond in time."
                    })

                except Exception as e:
                    errors.append({
                        "router": router_name,
                        "error": str(e)
                    })

        if errors:
            results.append({
                "_search_warnings": errors
            })

        return results
