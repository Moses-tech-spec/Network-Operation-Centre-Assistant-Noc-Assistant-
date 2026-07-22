from app.ai.root_cause import MayaRootCause


class MayaRemediation:

    @staticmethod
    def plan(router):

        report = MayaRootCause.analyze(router)

        cause = report["root_cause"].lower()

        actions = []

        # -----------------------------
        # BGP
        # -----------------------------

        if "bgp" in cause:

            actions = [

                "Verify upstream connectivity.",

                "Ping BGP neighbor.",

                "Verify interface status.",

                "Reset BGP session if reachable.",

                "Verify received prefixes.",

                "Monitor stability for 5 minutes."

            ]

        # -----------------------------
        # OSPF
        # -----------------------------

        elif "ospf" in cause:

            actions = [

                "Verify interface connectivity.",

                "Check OSPF authentication.",

                "Verify neighbor state.",

                "Restart OSPF adjacency if required."

            ]

        # -----------------------------
        # CPU
        # -----------------------------

        elif "cpu" in cause:

            actions = [

                "Identify top traffic source.",

                "Inspect firewall rules.",

                "Inspect routing processes.",

                "Inspect queues.",

                "Reduce unnecessary services."

            ]

        # -----------------------------
        # Memory
        # -----------------------------

        elif "memory" in cause:

            actions = [

                "Inspect connection tracking.",

                "Review active sessions.",

                "Restart unnecessary services.",

                "Schedule router reboot if required."

            ]

        # -----------------------------
        # Queue
        # -----------------------------

        elif "queue" in cause:

            actions = [

                "Inspect bandwidth utilization.",

                "Check queue hierarchy.",

                "Verify customer traffic.",

                "Adjust queue limits if necessary."

            ]

        # -----------------------------
        # Interface
        # -----------------------------

        elif "interface" in cause:

            actions = [

                "Check fiber link.",

                "Inspect SFP module.",

                "Check interface errors.",

                "Reset interface if safe."

            ]

        # -----------------------------
        # Firewall
        # -----------------------------

        elif "firewall" in cause:

            actions = [

                "Review recent rule changes.",

                "Verify rule order.",

                "Rollback recent modifications if needed."

            ]

        else:

            actions = [

                "Manual investigation recommended."

            ]

        return {

            "router": router,

            "root_cause": report["root_cause"],

            "confidence": report["confidence"],

            "plan": actions

        }
