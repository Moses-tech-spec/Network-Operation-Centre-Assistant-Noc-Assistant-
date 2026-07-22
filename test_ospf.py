from pprint import pprint

from app.services.ospf import OSPFCollector

pprint(OSPFCollector.collect())
