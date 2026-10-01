from app.config import ROUTERS
from app.routers.mikrotik import api, get_path, safe_str
from app.services.incident_utils import raise_incident, resolve_incidents

MANAGEMENT_SERVICES = ["telnet", "ftp", "www", "ssh", "api", "api-ssl", "winbox", "www-ssl"]
UNENCRYPTED_SERVICES = {"telnet", "ftp", "www"}


def _check_exposed_services(router_name):
    findings = []
    services = get_path(router_name, "ip", "service")

    for svc in services:
        name = safe_str(svc.get("name"))
        if name not in MANAGEMENT_SERVICES:
            continue

        disabled = str(svc.get("disabled", "false")).lower() == "true"
        address = safe_str(svc.get("address")).strip()
        category = f"POSTURE_SERVICE_{name.upper()}"

        if disabled:
            resolve_incidents(router_name, category)
            findings.append({"service": name, "status": "disabled"})
            continue

        if not address:
            severity = "CRITICAL" if name in UNENCRYPTED_SERVICES else "WARNING"
            note = " This protocol is unencrypted." if name in UNENCRYPTED_SERVICES else ""
            raise_incident(
                router=router_name,
                category=category,
                severity=severity,
                title=f"{name} service exposed with no address restriction",
                description=(
                    f"The '{name}' management service is enabled on {router_name} "
                    f"with no 'address' allow-list, meaning it is reachable from "
                    f"anywhere.{note}"
                ),
                source="Posture Scan"
            )
            findings.append({"service": name, "status": "exposed", "severity": severity})
        else:
            resolve_incidents(router_name, category)
            findings.append({"service": name, "status": "restricted"})

    return findings


def _check_default_admin(router_name):
    category = "POSTURE_DEFAULT_ADMIN"
    users = get_path(router_name, "user")

    default_admin = None
    for u in users:
        if safe_str(u.get("name")).lower() == "admin":
            default_admin = u
            break

    if default_admin and str(default_admin.get("disabled", "false")).lower() != "true":
        raise_incident(
            router=router_name,
            category=category,
            severity="WARNING",
            title="Default 'admin' account still enabled",
            description=(
                f"Router {router_name} still has the default 'admin' username "
                f"enabled. Attackers targeting MikroTik routers commonly try this "
                f"username first. Consider renaming or disabling it in favor of a "
                f"named account."
            ),
            source="Posture Scan"
        )
        return {"status": "present"}

    resolve_incidents(router_name, category)
    return {"status": "absent_or_disabled"}


def _check_full_group_users(router_name):
    category = "POSTURE_FULL_GROUP_USERS"
    users = get_path(router_name, "user")

    full_users = [
        safe_str(u.get("name")) for u in users
        if safe_str(u.get("group")).lower() == "full"
        and str(u.get("disabled", "false")).lower() != "true"
    ]
    other_full_users = [name for name in full_users if name.lower() != "admin"]

    if other_full_users:
        raise_incident(
            router=router_name,
            category=category,
            severity="WARNING",
            title="Multiple accounts with full admin privileges",
            description=(
                f"Router {router_name} has accounts beyond 'admin' in the 'full' "
                f"group: {', '.join(other_full_users)}. Review whether each still "
                f"needs full access, or should be moved to a more limited group."
            ),
            source="Posture Scan"
        )
        return {"status": "excess", "users": other_full_users}

    resolve_incidents(router_name, category)
    return {"status": "clean"}


def _check_firewall_input_chain(router_name):
    category = "POSTURE_FIREWALL_INPUT_OPEN"
    rules = get_path(router_name, "ip", "firewall", "filter")

    has_catch_all_drop = False
    for r in rules:
        if str(r.get("disabled", "false")).lower() == "true":
            continue
        if r.get("chain") != "input":
            continue
        if r.get("action") not in ("drop", "reject"):
            continue
        if not r.get("src-address") and not r.get("src-address-list") and not r.get("protocol"):
            has_catch_all_drop = True
            break

    if not has_catch_all_drop:
        raise_incident(
            router=router_name,
            category=category,
            severity="CRITICAL",
            title="No catch-all drop rule on input chain",
            description=(
                f"Router {router_name}'s firewall 'input' chain has no "
                f"unconditional drop/reject rule at the end. Without one, any "
                f"traffic not matched by an earlier rule is allowed to reach the "
                f"router's own services."
            ),
            source="Posture Scan"
        )
        return {"status": "open"}

    resolve_incidents(router_name, category)
    return {"status": "protected"}


def _check_routeros_version(router_name):
    category = "POSTURE_OUTDATED_ROUTEROS"
    try:
        connection = api(router_name)
        list(connection("/system/package/update/check-for-updates"))
        result = list(connection.path("system", "package", "update"))
    except Exception as e:
        return {"status": "error", "message": str(e)}

    if not result:
        return {"status": "unknown"}

    info = result[0]
    installed = info.get("installed-version")
    latest = info.get("latest-version")

    if latest and installed and latest != installed:
        raise_incident(
            router=router_name,
            category=category,
            severity="WARNING",
            title="RouterOS update available",
            description=(
                f"Router {router_name} is running RouterOS {installed}, but "
                f"{latest} is available. Newer releases often include security "
                f"fixes; review the changelog before upgrading."
            ),
            source="Posture Scan"
        )
        return {"status": "outdated", "installed": installed, "latest": latest}

    resolve_incidents(router_name, category)
    return {"status": "current", "installed": installed}


def run_posture_scan(include_version_check=True):
    results = []
    for router_name in ROUTERS:
        try:
            router_result = {
                "router": router_name,
                "services": _check_exposed_services(router_name),
                "default_admin": _check_default_admin(router_name),
                "full_group_users": _check_full_group_users(router_name),
                "firewall_input": _check_firewall_input_chain(router_name),
            }
            if include_version_check:
                router_result["routeros_version"] = _check_routeros_version(router_name)
            results.append(router_result)
        except Exception as e:
            results.append({"router": router_name, "error": str(e)})
    return results
