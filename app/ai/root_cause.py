from app.ai.correlation import MayaCorrelation


class MayaRootCause:

    @staticmethod
    def analyze(router):

        report = MayaCorrelation.analyze(router)

        findings = report["findings"]

        if not findings:

            return {
                "router": router,
                "root_cause": "No network abnormalities detected.",
                "confidence": 100,
                "severity": "healthy"
            }

        # Priority order
        priorities = {

            "BGP": 100,
            "Default route": 95,
            "OSPF": 90,
            "CPU": 80,
            "memory": 75,
            "queue": 70,
            "interface": 65,
            "firewall": 60,
            "incident": 50

        }

        score = 0
        cause = findings[0]["cause"]

        for finding in findings:

            text = finding["cause"].lower()

            for keyword, value in priorities.items():

                if keyword.lower() in text:

                    if value > score:

                        score = value
                        cause = finding["cause"]

        severity = "critical"

        if score < 80:
            severity = "warning"

        if score < 60:
            severity = "info"

        return {

            "router": router,

            "root_cause": cause,

            "confidence": score,

            "severity": severity,

            "evidence": findings

        }
