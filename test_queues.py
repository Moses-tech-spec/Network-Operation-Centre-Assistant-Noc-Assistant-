from pprint import pprint

from app.services.queues import QueueCollector

response = QueueCollector.collect()

pprint(response)
