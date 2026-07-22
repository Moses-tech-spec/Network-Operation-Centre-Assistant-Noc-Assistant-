from pprint import pprint

from app.services.firewall import FirewallCollector

pprint(

    FirewallCollector.collect()

)
