from pprint import pprint

from app.services.routes import RouteCollector

pprint(RouteCollector.collect())
