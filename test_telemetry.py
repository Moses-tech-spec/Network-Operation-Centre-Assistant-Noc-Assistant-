from pprint import pprint

from app.services.telemetry import TelemetryCollector

pprint(TelemetryCollector.collect())
