from app.ai.context import MayaContext


class MayaDiagnosis:

    """
    AI Diagnosis Engine

    Uses the complete router context instead
    of individual collectors.
    """

    @staticmethod
    def diagnose(router_name: str):

        context = MayaContext.router(router_name)

        telemetry = context["telemetry"]

        incidents = context["incidents"]

        inventory = context["inventory"]

        diagnosis = []

        if telemetry:

            cpu = telemetry.get("cpu_load", 0)

            memory_total = telemetry.get("memory_total", 0)

            memory_used = telemetry.get("memory_used", 0)

            if memory_total:

                memory_percent = round(
                    (memory_used / memory_total) * 100,
                    1
                )

            else:

                memory_percent = 0

            temperature = telemetry.get("temperature", 0)

            # -----------------------
            # CPU
            # -----------------------

            if cpu >= 90:

                diagnosis.append({

                    "component": "CPU",

                    "status": "CRITICAL",

                    "message": f"CPU utilization is {cpu}%"

                })

            elif cpu >= 75:

                diagnosis.append({

                    "component": "CPU",

                    "status": "WARNING",

                    "message": f"CPU utilization is {cpu}%"

                })

            else:

                diagnosis.append({

                    "component": "CPU",

                    "status": "HEALTHY",

                    "message": f"CPU utilization is {cpu}%"

                })

            # -----------------------
            # Memory
            # -----------------------

            if memory_percent >= 90:

                diagnosis.append({

                    "component": "Memory",

                    "status": "CRITICAL",

                    "message": f"Memory utilization is {memory_percent}%"

                })

            elif memory_percent >= 75:

                diagnosis.append({

                    "component": "Memory",

                    "status": "WARNING",

                    "message": f"Memory utilization is {memory_percent}%"

                })

            else:

                diagnosis.append({

                    "component": "Memory",

                    "status": "HEALTHY",

                    "message": f"Memory utilization is {memory_percent}%"

                })

            # -----------------------
            # Temperature
            # -----------------------

            if temperature >= 70:

                diagnosis.append({

                    "component": "Temperature",

                    "status": "CRITICAL",

                    "message": f"Temperature is {temperature}°C"

                })

            elif temperature >= 55:

                diagnosis.append({

                    "component": "Temperature",

                    "status": "WARNING",

                    "message": f"Temperature is {temperature}°C"

                })

            else:

                diagnosis.append({

                    "component": "Temperature",

                    "status": "HEALTHY",

                    "message": f"Temperature is {temperature}°C"

                })

        # -----------------------
        # Queue / Congestion
        # -----------------------

        queues = context.get("queues", [])  # will sort and cap to worst offenders below

        queue_flags = []

        for q in queues:

            try:
                up_limit, down_limit = [int(x) for x in q.get("max_limit", "0/0").split("/")]
            except Exception:
                up_limit, down_limit = 0, 0

            up_rate = q.get("upload_rate") or 0
            down_rate = q.get("download_rate") or 0

            up_util = round((up_rate / up_limit) * 100, 1) if up_limit else 0
            down_util = round((down_rate / down_limit) * 100, 1) if down_limit else 0

            worst = max(up_util, down_util)
            dropped = (q.get("upload_dropped") or 0) + (q.get("download_dropped") or 0)

            if worst >= 90 or dropped > 0:
                queue_flags.append((dropped, worst, {
                    "component": "Queue",
                    "status": "CRITICAL",
                    "message": f"Queue '{q.get('queue_name')}' is at {worst}% of max bandwidth (dropped packets: {dropped}) — likely causing slowness"
                }))

            elif worst >= 70:
                queue_flags.append((dropped, worst, {
                    "component": "Queue",
                    "status": "WARNING",
                    "message": f"Queue '{q.get('queue_name')}' is at {worst}% of max bandwidth"
                }))

        # Only surface the 5 worst offenders — a NOC engineer needs the
        # headline, not a per-customer dump of every flagged queue.
        queue_flags.sort(key=lambda x: (x[0], x[1]), reverse=True)
        total_flagged = len(queue_flags)

        for _, _, entry in queue_flags[:5]:
            diagnosis.append(entry)

        if total_flagged > 5:
            diagnosis.append({
                "component": "Queue",
                "status": "INFO",
                "message": f"{total_flagged - 5} additional queue(s) also flagged but omitted for brevity — {total_flagged} total flagged out of {len(queues)} queues checked."
            })

        return {

            "router": router_name,

            "identity": inventory.get("identity") if inventory else None,

            "diagnosis": diagnosis,

            "open_incidents": len(incidents),

            "context": context

        }
