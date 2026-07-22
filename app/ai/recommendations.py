from app.ai.diagnosis import MayaDiagnosis


class MayaRecommendations:

    @staticmethod
    def recommend(router):

        report = MayaDiagnosis.diagnose(router)

        recommendations = []

        telemetry = report["context"].get("telemetry", {})

        cpu = telemetry.get("cpu_load", 0)

        memory_total = telemetry.get("memory_total", 1)
        memory_used = telemetry.get("memory_used", 0)

        memory_percent = round(
            (memory_used / memory_total) * 100,
            1
        ) if memory_total else 0

        temperature = telemetry.get("temperature", 0)

        incidents = report.get("open_incidents", 0)

        # CPU
        if cpu >= 90:
            recommendations.extend([
                "Inspect routing processes.",
                "Check firewall rules.",
                "Review queue utilization.",
                "Inspect routing protocols.",
                "Consider redistributing customer traffic."
            ])
        elif cpu >= 75:
            recommendations.append(
                "Monitor CPU utilization."
            )

        # Memory
        if memory_percent >= 90:
            recommendations.extend([
                "Inspect memory leaks.",
                "Reduce connection tracking.",
                "Review firewall connections."
            ])
        elif memory_percent >= 75:
            recommendations.append(
                "Monitor memory utilization."
            )

        # Temperature
        if temperature >= 70:
            recommendations.extend([
                "Inspect cooling system.",
                "Verify fan operation.",
                "Check room temperature."
            ])
        elif temperature >= 55:
            recommendations.append(
                "Monitor router temperature."
            )

        # Incidents
        if incidents > 0:
            recommendations.append(
                "Review unresolved incidents."
            )

        # Queue / Congestion
        for item in report["diagnosis"]:
            if item.get("component") == "Queue":
                if item.get("status") == "CRITICAL":
                    recommendations.append(
                        f"Investigate bandwidth congestion: {item.get('message')}"
                    )
                elif item.get("status") == "WARNING":
                    recommendations.append(
                        f"Monitor queue utilization: {item.get('message')}"
                    )

        if not recommendations:
            recommendations.append(
                "Router is operating normally."
            )

        return {
            "router": router,
            "diagnosis": report["diagnosis"],
            "recommendations": recommendations,
            "context": report["context"]
        }
