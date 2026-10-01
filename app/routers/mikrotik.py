from librouteros import connect
import time
from datetime import datetime
from app.config import ROUTERS


# ==========================================================
# Router Connection
# ==========================================================

def api(router_name):
    """
    Connect to a MikroTik router.
    """

    if router_name not in ROUTERS:
        raise Exception(f"Router '{router_name}' not found.")

    router = ROUTERS[router_name]

    return connect(
        host=router["host"],
        username=router["username"],
        password=router["password"],
        port=router["port"],
    )


# ==========================================================
# Helper Functions
# ==========================================================

def bytes_to_mb(value):
    try:
        return round(int(value) / 1024 / 1024)
    except:
        return 0


def get_path(router_name, *path):
    return list(api(router_name).path(*path))


def format_collection(router_name, key, data):

    return {
        "router": router_name,
        "count": len(data),
        key: data,
    }


def safe_str(value):

    if value is None:
        return ""

    return str(value)


# ==========================================================
# SYSTEM
# ==========================================================

def get_system_resource(router_name):

    resource = get_path(router_name, "system", "resource")[0]
    identity = get_path(router_name, "system", "identity")[0]

    return {
        "router": router_name,
        "status": "online",
        "system": {
            "identity": identity.get("name"),
            "version": resource.get("version"),
            "uptime": resource.get("uptime"),
            "platform": resource.get("platform"),
            "board": resource.get("board-name"),
            "architecture": resource.get("architecture-name"),
            "cpu": {
                "load": int(resource.get("cpu-load", 0)),
                "count": int(resource.get("cpu-count", 1)),
                "frequency_mhz": int(resource.get("cpu-frequency", 0)),
            },
            "memory": {
                "total_mb": bytes_to_mb(resource.get("total-memory", 0)),
                "free_mb": bytes_to_mb(resource.get("free-memory", 0)),
            },
            "storage": {
                "total_mb": bytes_to_mb(resource.get("total-hdd-space", 0)),
                "free_mb": bytes_to_mb(resource.get("free-hdd-space", 0)),
            },
        },
    }


# ==========================================================
# INTERFACES
# ==========================================================

def get_interfaces(router_name):

    interfaces = get_path(router_name, "interface")

    output = []

    for interface in interfaces:

        output.append({

            "name": interface.get("name"),
            "type": interface.get("type"),
            "running": interface.get("running"),
            "disabled": interface.get("disabled"),
            "mtu": interface.get("mtu"),
            "mac_address": interface.get("mac-address"),
            "rx_bytes": int(interface.get("rx-byte", 0)),
            "tx_bytes": int(interface.get("tx-byte", 0)),
            "rx_packets": int(interface.get("rx-packet", 0)),
            "tx_packets": int(interface.get("tx-packet", 0)),

        })

    return format_collection(router_name, "interfaces", output)


# ==========================================================
# LIVE TRAFFIC
# ==========================================================

def get_traffic(router_name, interface_name):

    connection = api(router_name)

    result = list(
        connection(
            cmd="/interface/monitor-traffic",
            **{
                "interface": interface_name,
                "once": True,
            }
        )
    )

    if not result:

        return {
            "router": router_name,
            "interface": interface_name,
            "message": "No data returned."
        }

    data = result[0]

    rx = int(data.get("rx-bits-per-second", 0))
    tx = int(data.get("tx-bits-per-second", 0))

    return {

        "router": router_name,

        "interface": interface_name,

        "rx_bps": rx,

        "tx_bps": tx,

        "rx_mbps": round(rx / 1000000, 2),

        "tx_mbps": round(tx / 1000000, 2),

    }


# ==========================================================
# ACTIVE PPPOE USERS
# ==========================================================

def get_pppoe(router_name):

    sessions = get_path(router_name, "ppp", "active")

    users = []

    for session in sessions:

        users.append({

            ".id": session.get(".id"),

            "username": session.get("name"),

            "address": session.get("address"),

            "caller_id": session.get("caller-id"),

            "service": session.get("service"),

            "uptime": session.get("uptime"),

        })

    return {

        "router": router_name,

        "active_users": len(users),

        "users": users,

    }


# ==========================================================
# SIMPLE QUEUES
# ==========================================================

def get_queues(router_name):

    queues = get_path(router_name, "queue", "simple")

    output = []

    for queue in queues:

        output.append({

            "name": queue.get("name"),

            "target": queue.get("target"),

            "max_limit": queue.get("max-limit"),

            "disabled": queue.get("disabled"),

        })

    return format_collection(router_name, "queues", output)


# ==========================================================
# DHCP LEASES
# ==========================================================

def get_leases(router_name):

    leases = get_path(router_name, "ip", "dhcp-server", "lease")

    output = []

    for lease in leases:

        output.append({

            "ip": lease.get("address"),

            "mac": lease.get("mac-address"),

            "hostname": lease.get("host-name"),

            "status": lease.get("status"),

            "server": lease.get("server"),

        })

    return format_collection(router_name, "leases", output)


# ==========================================================
# LOGS
# ==========================================================

def get_logs(router_name):

    logs = get_path(router_name, "log")

    output = []

    for log in logs:

        output.append({

            "time": log.get("time"),

            "topics": log.get("topics"),

            "message": log.get("message"),

        })

    return format_collection(router_name, "logs", output)


# ==========================================================
# CUSTOMER SEARCH
# ==========================================================

def search_customer(router_name, query):

    q = safe_str(query).lower()

    pppoe = get_pppoe(router_name)["users"]
    leases = get_leases(router_name)["leases"]
    queues = get_queues(router_name)["queues"]

    result = {

        "query": query,

        "router": router_name,

        "match_found": False,

        "pppoe": None,

        "lease": None,

        "queue": None,

    }

    for user in pppoe:

        if q in safe_str(user["username"]).lower() or q in safe_str(user["address"]).lower():

            result["pppoe"] = user

            result["match_found"] = True

            break

    for lease in leases:

        if q in safe_str(lease["hostname"]).lower() or q in safe_str(lease["ip"]).lower():

            result["lease"] = lease

            result["match_found"] = True

            break

    for queue in queues:

        if q in safe_str(queue["name"]).lower():

            result["queue"] = queue

            result["match_found"] = True

            break

    if not result["match_found"]:

        return {

            "router": router_name,

            "query": query,

            "match_found": False,

            "message": "Customer not found"

        }

    return result


# ==========================================================
# DISCONNECT PPPOE
# ==========================================================

def disconnect_pppoe(router_name, username):

    customer = search_customer(router_name, username)

    if not customer["match_found"]:

        return {

            "success": False,

            "message": "Customer not found."

        }

    session = customer["pppoe"]

    if session is None:

        return {

            "success": False,

            "message": "Customer is currently offline."

        }

    api(router_name).path(
        "ppp",
        "active"
    ).remove(session[".id"])

    return {

        "success": True,

        "customer": session["username"],

        "router": router_name,

        "message": "Customer disconnected successfully."

    }


# ==========================================================
# Compatibility
# ==========================================================

def get_router_connection(router_name):
    """
    Backward compatibility for older modules.
    Returns a RouterOS API connection.
    """
    return api(router_name)


# ==========================================================
# PING (run from the router itself, reaches customer subnets)
# ==========================================================

def ping_host(router_name, address, count=4):

    if not address:
        return {"reachable": False, "error": "No address provided"}

    try:
        connection = api(router_name)

        results = list(
            connection(
                "/ping",
                address=address,
                count=str(count),
            )
        )

    except Exception as e:
        return {"reachable": False, "error": str(e)}

    if not results:
        return {"reachable": False, "error": "No ping response received"}

    # RouterOS includes running/final 'sent', 'received', 'packet-loss'
    # fields on each reply. The LAST entry reflects the final cumulative
    # state after all echoes complete — trust it directly instead of
    # recomputing from individual 'time' values.
    summary = results[-1]

    try:
        sent = int(summary.get("sent", count))
    except Exception:
        sent = count

    try:
        received = int(summary.get("received", 0))
    except Exception:
        received = 0

    try:
        packet_loss = float(summary.get("packet-loss", 100))
    except Exception:
        packet_loss = round(((sent - received) / sent) * 100, 1) if sent else 100

    def _parse_ms(val):
        if not val:
            return None
        val = str(val)
        try:
            if val.endswith("ms"):
                return float(val[:-2])
            elif val.endswith("us"):
                return float(val[:-2]) / 1000
            else:
                return float(val)
        except Exception:
            return None

    avg_rtt_raw = summary.get("avg-rtt") or summary.get("time")
    avg_rtt = _parse_ms(avg_rtt_raw)

    # Collect individual per-packet RTT samples (each non-summary reply
    # carries its own 'time' field) so we can measure jitter — the
    # variance between consecutive pings — rather than just an average.
    # High jitter with a fine average RTT is a classic buffering signature.
    rtt_samples = []
    for r in results:
        t = _parse_ms(r.get("time"))
        if t is not None:
            rtt_samples.append(t)

    min_rtt = round(min(rtt_samples), 2) if rtt_samples else None
    max_rtt = round(max(rtt_samples), 2) if rtt_samples else None
    jitter_ms = None
    if len(rtt_samples) >= 2:
        diffs = [abs(rtt_samples[i] - rtt_samples[i - 1]) for i in range(1, len(rtt_samples))]
        jitter_ms = round(sum(diffs) / len(diffs), 2)

    return {
        "reachable": received > 0,
        "sent": sent,
        "received": received,
        "packet_loss_percent": packet_loss,
        "avg_rtt_ms": avg_rtt,
        "min_rtt_ms": min_rtt,
        "max_rtt_ms": max_rtt,
        "jitter_ms": jitter_ms,
    }


# ==========================================================
# BLOCK / UNBLOCK CUSTOMER
# ==========================================================

def block_customer(router_name, query):
    """
    SOFT BLOCK: kills the customer's active PPPoE session.
    NOTE: since this deployment does not use /ppp/secret (clients
    authenticate via RADIUS onto Active Connections directly), this
    is temporary — the customer may be able to reconnect on their own.
    For a persistent block, a firewall address-list rule is required.
    """

    connection = api(router_name)

    active_sessions = get_path(router_name, "ppp", "active")
    q = safe_str(query).lower()
    target_session = None

    for session in active_sessions:
        if q in safe_str(session.get("name")).lower():
            target_session = session
            break

    if not target_session:
        return {
            "success": False,
            "message": f"No active PPPoE session found matching '{query}'."
        }

    connection.path("ppp", "active").remove(target_session[".id"])

    return {
        "success": True,
        "customer": target_session.get("name"),
        "router": router_name,
        "message": "Active session terminated. This is a temporary disconnect — the customer may reconnect since no local PPPoE secret controls their access."
    }


def unblock_customer(router_name, query):
    """
    Placeholder: with no /ppp/secret in use, there is nothing local
    to re-enable. If a firewall address-list block is later added,
    this function should remove the entry from that list instead.
    """

    return {
        "success": False,
        "message": "Unblock is not applicable in the current setup — no PPPoE secret exists to re-enable. If blocking is implemented via a firewall address-list, this function will be updated to remove the customer from that list."
    }


# ==========================================================
# ENABLE / DISABLE QUEUE BY IP / SUBNET
# ==========================================================

import ipaddress


def _ip_matches_target(ip_input, target_str):
    """
    Returns True if ip_input (host IP or subnet, with or without /mask)
    falls within target_str (a queue's target, e.g. '10.10.4.0/30').
    """

    if not target_str:
        return False

    try:
        network = ipaddress.ip_network(target_str.strip(), strict=False)
    except Exception:
        return False

    try:
        candidate = ip_input.strip()
        if "/" in candidate:
            candidate_addr = ipaddress.ip_network(candidate, strict=False).network_address
        else:
            candidate_addr = ipaddress.ip_address(candidate)
    except Exception:
        return False

    return candidate_addr in network


def find_queue_by_ip(ip_input):
    """
    Searches all routers' simple queues for one whose target matches
    the given IP or subnet. Returns the first match, or None.
    """

    for router_name in ROUTERS:

        try:
            queues = get_path(router_name, "queue", "simple")
        except Exception:
            continue

        for q in queues:

            target_field = safe_str(q.get("target"))

            for t in target_field.split(","):
                if _ip_matches_target(ip_input, t):
                    return {
                        "router": router_name,
                        "queue": q,
                        "matched_target": t.strip(),
                    }

    return None


def set_queue_state_by_ip(ip_input, disabled: bool):
    """
    Finds the queue matching the given IP/subnet and enables or disables it.
    """

    found = find_queue_by_ip(ip_input)

    if not found:
        return {
            "success": False,
            "message": f"No queue found matching IP/subnet '{ip_input}'."
        }

    router_name = found["router"]
    queue = found["queue"]

    connection = api(router_name)

    connection.path("queue", "simple").update(
        **{".id": queue[".id"], "disabled": "true" if disabled else "false"}
    )

    action = "disabled" if disabled else "enabled"

    return {
        "success": True,
        "router": router_name,
        "queue_name": queue.get("name") or queue.get("comment") or "unnamed",
        "target": found["matched_target"],
        "message": f"Queue for {found['matched_target']} has been {action}."
    }


# ==========================================================
# WEBSITE / ROUTE REACHABILITY DIAGNOSTICS
# ==========================================================

import socket


def resolve_hostname(hostname):
    """
    Resolves a domain name to an IP address. Runs on the API server,
    not the router, so it reflects public DNS — useful baseline even
    if a customer's own DNS resolution is the actual problem.
    """
    try:
        return socket.gethostbyname(hostname)
    except Exception as e:
        return None


def find_best_route(router_name, target_ip):
    """
    Finds the most specific (longest-prefix-match) active route on
    the router for reaching target_ip — mimics how the router itself
    would choose a route.
    """

    try:
        routes = get_path(router_name, "ip", "route")
    except Exception:
        return None

    best = None
    best_prefix = -1

    for r in routes:

        if str(r.get("disabled", "false")).lower() == "true":
            continue

        dst = safe_str(r.get("dst-address"))
        if not dst:
            continue

        try:
            network = ipaddress.ip_network(dst, strict=False)
        except Exception:
            continue

        try:
            if ipaddress.ip_address(target_ip) in network:
                if network.prefixlen > best_prefix:
                    best_prefix = network.prefixlen
                    best = {
                        "dst_address": dst,
                        "gateway": r.get("gateway"),
                        "distance": r.get("distance"),
                        "active": r.get("active"),
                    }
        except Exception:
            continue

    return best


def traceroute_host(router_name, target_ip, max_hops=15):
    """
    Runs a live traceroute from the router itself to target_ip.
    Takes several seconds to complete since it waits for the full path.
    """

    try:
        connection = api(router_name)

        results = list(
            connection(
                "/tool/traceroute",
                address=target_ip,
                count="1",
                **{"max-hops": str(max_hops)}
            )
        )

    except Exception as e:
        return {"error": str(e)}

    hops = []
    for r in results:
        hops.append({
            "hop": r.get("hop"),
            "address": r.get("address"),
            "status": r.get("status"),
            "time": r.get("last") or r.get("time"),
            "loss_percent": r.get("loss"),
        })

    return {"hops": hops}


def check_firewall_block(router_name, target_ip):
    """
    Checks enabled drop/reject firewall filter rules for anything
    matching target_ip, either directly or via a referenced
    address-list.
    """

    try:
        rules = get_path(router_name, "ip", "firewall", "filter")
    except Exception:
        return []

    matches = []

    address_list_cache = {}

    for rule in rules:

        if str(rule.get("disabled", "false")).lower() == "true":
            continue

        if rule.get("action") not in ("drop", "reject"):
            continue

        matched = False

        dst_addr = safe_str(rule.get("dst-address"))
        if dst_addr:
            try:
                if ipaddress.ip_address(target_ip) in ipaddress.ip_network(dst_addr, strict=False):
                    matched = True
            except Exception:
                pass

        dst_list = safe_str(rule.get("dst-address-list"))
        if not matched and dst_list:

            if dst_list not in address_list_cache:
                try:
                    address_list_cache[dst_list] = get_path(router_name, "ip", "firewall", "address-list")
                except Exception:
                    address_list_cache[dst_list] = []

            for entry in address_list_cache[dst_list]:
                if entry.get("list") != dst_list:
                    continue
                try:
                    if ipaddress.ip_address(target_ip) in ipaddress.ip_network(safe_str(entry.get("address")), strict=False):
                        matched = True
                        break
                except Exception:
                    continue

        if matched:
            matches.append({
                "chain": rule.get("chain"),
                "action": rule.get("action"),
                "comment": rule.get("comment"),
                "dst_address": dst_addr or None,
                "dst_address_list": dst_list or None,
            })

    return matches


def check_website_access(target_hostname):
    """
    Resolves target_hostname once, then checks EVERY configured router
    for: the route it would use, a live traceroute, and any firewall
    rule that would block reaching it.
    """

    resolved_ip = resolve_hostname(target_hostname)

    if not resolved_ip:
        return {
            "target": target_hostname,
            "error": f"Could not resolve '{target_hostname}' to an IP address."
        }

    router_results = {}

    for router_name in ROUTERS:

        route = find_best_route(router_name, resolved_ip)
        trace = traceroute_host(router_name, resolved_ip)
        blocks = check_firewall_block(router_name, resolved_ip)

        router_results[router_name] = {
            "route": route,
            "traceroute": trace,
            "blocking_rules": blocks,
        }

    return {
        "target": target_hostname,
        "resolved_ip": resolved_ip,
        "routers": router_results,
    }


# ==========================================================
# RECONNECT CUSTOMER
# ==========================================================

def reconnect_customer(router_name, query):
    """
    PPPoE reconnection is client-initiated by protocol design — the
    router cannot force a remote customer's equipment to redial.
    This function ensures nothing on OUR side is blocking them
    (re-enables their PPP secret if disabled) and reports honestly
    on what was actually done.
    """

    connection = api(router_name)

    secrets = get_path(router_name, "ppp", "secret")
    q = safe_str(query).lower()
    target_secret = None

    for secret in secrets:
        if q in safe_str(secret.get("name")).lower():
            target_secret = secret
            break

    if not target_secret:
        return {
            "success": False,
            "message": f"No PPPoE secret found for '{query}' on {router_name}. If this router uses RADIUS authentication instead of local secrets, there is nothing on this router blocking them — reconnection is fully client-initiated and cannot be forced remotely."
        }

    was_disabled = str(target_secret.get("disabled", "false")).lower() == "true"

    if was_disabled:
        connection.path("ppp", "secret").update(
            **{".id": target_secret[".id"], "disabled": "false"}
        )
        message = f"'{target_secret.get('name')}' was blocked (secret disabled) — it has now been re-enabled. Their equipment should redial and reconnect automatically within seconds to a couple of minutes."
    else:
        message = f"'{target_secret.get('name')}' was not blocked on this router. Reconnection is entirely initiated by the customer's own equipment — nothing further can be done remotely to force it. If they remain offline, the issue is likely on their end (power/cable/CPE) or upstream, not something Maya can push through."

    return {
        "success": True,
        "customer": target_secret.get("name"),
        "router": router_name,
        "was_blocked": was_disabled,
        "message": message
    }


# ==========================================================
# RESET PPP SESSION
# ==========================================================

def reset_ppp_session(router_name, query):
    """
    Forces a fresh re-authentication by killing the customer's current
    active session (same underlying action as disconnect, but framed
    as a non-destructive troubleshooting step rather than a punitive
    disconnect — does not touch their PPP secret / block status).
    """

    active_sessions = get_path(router_name, "ppp", "active")
    q = safe_str(query).lower()
    target_session = None

    for session in active_sessions:
        if q in safe_str(session.get("name")).lower():
            target_session = session
            break

    if not target_session:
        return {
            "success": False,
            "message": f"No active PPPoE session found for '{query}' on {router_name} — they may already be offline."
        }

    connection = api(router_name)
    connection.path("ppp", "active").remove(target_session[".id"])

    return {
        "success": True,
        "customer": target_session.get("name"),
        "router": router_name,
        "message": "Session reset — their connection was dropped and should automatically re-authenticate. This does not affect their account status."
    }


# ==========================================================
# RESTART INTERFACE
# ==========================================================

def restart_interface(router_name, interface_name):
    """
    Bounces an interface by disabling then re-enabling it. RouterOS
    has no direct 'restart' command for most interface types via API —
    this achieves the same practical effect.
    """

    connection = api(router_name)

    interfaces = get_path(router_name, "interface")
    target = None

    q = safe_str(interface_name).lower()
    for iface in interfaces:
        if safe_str(iface.get("name")).lower() == q:
            target = iface
            break

    if not target:
        return {
            "success": False,
            "message": f"No interface named '{interface_name}' found on {router_name}."
        }

    iface_id = target[".id"]

    try:
        connection.path("interface").update(**{".id": iface_id, "disabled": "true"})
        time.sleep(2)
        connection.path("interface").update(**{".id": iface_id, "disabled": "false"})
    except Exception as e:
        return {
            "success": False,
            "message": f"Error restarting interface: {str(e)}"
        }

    return {
        "success": True,
        "router": router_name,
        "interface": interface_name,
        "message": f"Interface '{interface_name}' on {router_name} was disabled and re-enabled (restarted)."
    }


# ==========================================================
# BACKUP ROUTER
# ==========================================================

def backup_router(router_name):
    """
    Triggers RouterOS to save a backup file ON THE ROUTER ITSELF via
    /system/backup/save. Does NOT download the file to this server —
    that would require FTP/SFTP access as a separate step.
    """

    connection = api(router_name)

    backup_name = f"{router_name}-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    try:
        list(
            connection(
                "/system/backup/save",
                name=backup_name,
            )
        )
    except Exception as e:
        return {
            "success": False,
            "message": f"Backup failed on {router_name}: {str(e)}"
        }

    return {
        "success": True,
        "router": router_name,
        "backup_name": f"{backup_name}.backup",
        "message": f"Backup '{backup_name}.backup' created and saved on {router_name}'s local file storage. Note: this file is on the router itself, not yet downloaded to the API server — that requires FTP/SFTP access as a separate step if needed."
    }


def reboot_router(router_name):
    """
    Reboots the router via the RouterOS API. The connection drops
    immediately once the command is sent (expected -- the router is
    restarting), so we treat that as a normal outcome rather than
    an error.
    """

    if router_name not in ROUTERS:
        return {"success": False, "message": f"Router '{router_name}' not found."}

    try:
        connection = api(router_name)
        list(connection("/system/reboot"))
    except Exception:
        # Connection drop is expected once the reboot command is sent.
        pass

    return {
        "success": True,
        "router": router_name,
        "message": f"Reboot command sent to {router_name}. It will be unreachable for a minute or two while it restarts."
    }


def backup_all_routers():
    results = []
    for router_name in ROUTERS:
        try:
            results.append(backup_router(router_name))
        except Exception as e:
            results.append({"success": False, "router": router_name, "message": str(e)})
    return results
