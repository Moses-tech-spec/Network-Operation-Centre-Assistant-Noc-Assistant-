from app.ai.network_intelligence import NetworkIntelligence


class MayaCorrelation:

    @staticmethod
    def analyze(router):

        data = NetworkIntelligence.collect(router)

        findings = []

        health = data["health"] or {}

        cpu = health.get("cpu_load", 0)

        memory_used = health.get("memory_used", 0)
        memory_total = health.get("memory_total", 1)

        memory = 0

        if memory_total:

            memory = (memory_used / memory_total) * 100

        queues = data["queues"]
        bgp = data["bgp"]
        ospf = data["ospf"]
        routes = data["routes"]
        interfaces = data["interfaces"]
        firewall = data["firewall"]
        incidents = data["incidents"]

        # ===================================
        # CPU
        # ===================================

        if cpu >= 90:

            findings.append({

                "severity": "critical",

                "cause": "Router CPU overloaded"

            })

        # ===================================
        # Memory
        # ===================================

        if memory >= 90:

            findings.append({

                "severity": "critical",

                "cause": "Router memory exhausted"

            })

        # ===================================
        # Queue Congestion
        # ===================================

        heavy = []

        for q in queues:

            if q.get("upload_rate", 0) > 10000000:

                heavy.append(q["queue_name"])

        if heavy:

            findings.append({

                "severity": "warning",

                "cause": f"Heavy queue utilization ({len(heavy)} queues)"

            })

        # ===================================
        # BGP
        # ===================================

        for peer in bgp:

            if peer.get("state") != "ACTIVE":

                findings.append({

                    "severity": "critical",

                    "cause": f"BGP peer {peer['peer_name']} is down"

                })

        # ===================================
        # OSPF
        # ===================================

        for neighbor in ospf:

            if neighbor.get("state") != "Full":

                findings.append({

                    "severity": "warning",

                    "cause": f"OSPF neighbor {neighbor['neighbor_id']} unstable"

                })

        # ===================================
        # Routes
        # ===================================

        defaults = [

            r for r in routes

            if r.get("destination") == "0.0.0.0/0"

        ]

        if len(defaults) == 0:

            findings.append({

                "severity": "critical",

                "cause": "Default route missing"

            })

        # ===================================
        # Interfaces
        # ===================================

        for iface in interfaces:

            if iface.get("rx_errors", 0) > 0:

                findings.append({

                    "severity": "warning",

                    "cause": f"Errors detected on {iface['interface_name']}"

                })

        # ===================================
        # Firewall
        # ===================================

        disabled = [

            f for f in firewall

            if f.get("disabled")

        ]

        if len(disabled) > 20:

            findings.append({

                "severity": "info",

                "cause": "Large number of disabled firewall rules"

            })

        # ===================================
        # Existing Incidents
        # ===================================

        if incidents:

            findings.append({

                "severity": "info",

                "cause": f"{len(incidents)} unresolved incidents"

            })

        return {

            "router": router,

            "findings": findings

        }
