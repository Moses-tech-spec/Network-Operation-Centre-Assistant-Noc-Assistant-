from pprint import pprint

from app.services.bgp import BGPCollector

pprint(BGPCollector.collect())
