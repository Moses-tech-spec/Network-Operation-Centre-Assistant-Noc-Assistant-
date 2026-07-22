def analyze_customer(customer):

    checks = {}
    issues = []
    steps = []

    is_pppoe_customer = bool(customer.get("pppoe")) or bool(customer.get("pppoe_secret"))

    # PPPoE
    if customer.get("pppoe"):
        checks["pppoe"] = "Connected"
    else:
        checks["pppoe"] = "Offline"
        issues.append("PPPoE session not active")
        steps.append(
            "PPPoE session is down: check power to the customer's ONU/router/CPE, "
            "verify the physical fiber/cable connection for damage or disconnection, "
            "and check RADIUS/PPPoE authentication logs on the router for failed login attempts."
        )

    # Queue
    queue = customer.get("queue")

    if queue:

        disabled = str(queue.get("disabled", "false")).lower()

        if disabled == "true":
            checks["queue"] = "Disabled"
            issues.append("Simple Queue is disabled")
            steps.append(
                "Simple Queue is disabled: re-enable the queue on the router. "
                "If this customer was previously blocked for non-payment or abuse, "
                "confirm whether the disable was intentional before re-enabling."
            )
        else:
            checks["queue"] = "Enabled"

    else:
        checks["queue"] = "Missing"
        issues.append("Simple Queue not found")
        steps.append(
            "No Simple Queue found for this customer: confirm they are provisioned "
            "correctly and that the queue name matches the expected naming convention "
            "(e.g. <pppoe-username>). Without a queue, bandwidth cannot be shaped or throttled."
        )

    # DHCP lease — only relevant for customers NOT on PPPoE.
    # PPPoE customers get their IP from the PPP pool, not DHCP, so a missing
    # lease is expected and should not be flagged as a fault.
    lease = customer.get("lease")

    if is_pppoe_customer:
        checks["lease"] = "Not applicable (PPPoE customer — IP assigned via PPP pool)"
    elif lease:

        status = str(lease.get("status", "")).lower()

        if status == "bound":
            checks["lease"] = "Bound"
        else:
            checks["lease"] = status
            issues.append(f"Lease status is {status}")
            steps.append(
                f"DHCP lease status is '{status}' instead of bound: check the DHCP "
                "server is running on the router, confirm the customer's device is "
                "requesting an address, and check for IP pool exhaustion."
            )

    else:
        checks["lease"] = "Missing"
        issues.append("DHCP lease not found")
        steps.append(
            "No DHCP lease found for this non-PPPoE customer: verify the customer's "
            "device is powered on and connected, check the DHCP server is running "
            "on the correct interface, and confirm the customer's MAC address isn't "
            "blocked or excluded from the pool."
        )

    health = 100 - (len(issues) * 25)

    if health < 0:
        health = 0

    if not issues:
        recommendation = "Customer operating normally. No action needed."
    else:
        recommendation = " ".join(steps)

    return {
        "customer": customer["query"],
        "router": customer["router"],
        "status": "ONLINE" if health == 100 else "PROBLEM",
        "health_score": health,
        "checks": checks,
        "issues": issues,
        "recommendation": recommendation,
    }
