import re

from app.ai.recommendations import MayaRecommendations
from app.analyzer import analyze_customer
from app.ai.memory import MayaMemory
from app.ai.ollama import ask_llm
from app.services.search import UniversalSearch
from app.services.incidents import IncidentEngine
from app.routers.mikrotik import (
    ping_host,
    block_customer,
    unblock_customer,
    set_queue_state_by_ip,
    disconnect_pppoe,
    check_website_access,
    reconnect_customer,
    reset_ppp_session,
    restart_interface,
    backup_router,
    backup_all_routers,
)
from app.services.config_backup import propose_firewall_rule
from app.services.config_backup import summarize_router_config
from app.services.config_backup import get_raw_router_config
from app.services.config_backup import get_config_section
from app.services.posture import (
    _check_exposed_services,
    _check_default_admin,
    _check_full_group_users,
    _check_firewall_input_chain,
    _check_routeros_version,
)
from app.services.ppp_anomaly import _check_flapping, _check_mass_disconnect
from app.services.traffic_anomaly import _check_zero_traffic, _check_spike, _distinct_interfaces
from app.routers.mikrotik import get_logs
from app.config import ROUTERS


ROUTER_ALIASES = {
    # "office": "actual_router_key",
}

STOPWORDS = {
    "why", "is", "the", "a", "an", "are", "was", "were", "be",
    "slow", "down", "offline", "online", "healthy", "unhealthy",
    "router", "customer", "connection", "internet", "network",
    "what", "how", "many", "much", "does", "do", "for", "of",
    "to", "in", "on", "at", "and", "with", "status", "check",
    "show", "me", "please", "can", "you", "tell", "about",
    "disconnect", "block", "unblock", "scan", "incidents", "incident",
    "reachable", "right", "now", "currently", "still", "again",
    "there", "yet", "already", "reconnect", "restart", "backup",
    "reset", "session", "interface", "ppp",
}

PRONOUNS = {
    "it", "him", "her", "them", "he", "she", "this", "that",
    "they", "their", "his", "hers", "its",
}


def is_pronoun_only(question: str) -> bool:
    """
    True if the question references something via pronoun (her, it,
    that customer, etc.) with no other identifying name/word present —
    meaning it's referring back to something mentioned earlier rather
    than naming it directly.
    """
    tokens = re.findall(r"[a-z0-9.]+", question.lower())
    kept = [t for t in tokens if t not in STOPWORDS]

    if not kept:
        return True

    has_pronoun = any(t in PRONOUNS for t in kept)
    non_pronoun_kept = [t for t in kept if t not in PRONOUNS]

    return has_pronoun and not non_pronoun_kept


def resolve_last_mentioned(history, routers):
    """
    Scans prior user turns (most recent first) for the last router
    or customer name mentioned, so pronoun references can be resolved.
    """

    last_router = None
    last_customer = None

    if not history:
        return last_router, last_customer

    for msg in reversed(history):
        if msg.get("role") != "user":
            continue

        content = (msg.get("content") or "").lower()

        if not last_router:
            for router in routers:
                if router["router"].lower() in content:
                    last_router = router["router"]
                    break

        if not last_customer:
            tokens = re.findall(r"[a-z0-9.]+", content)
            kept = [t for t in tokens if t not in STOPWORDS and t not in PRONOUNS]
            if kept:
                last_customer = " ".join(kept).strip()

        if last_router and last_customer:
            break

    return last_router, last_customer

RESPONSE_STYLE_INSTRUCTIONS = """
Formatting rules:
- Do NOT repeat the phrases "User Question" or "Answer:" in your response.
- Do NOT restate the question back to the user.
- Respond directly with the information, structured as:

Status: (one line — Online/Offline/Healthy/Degraded/etc.)
Diagnosis: (what the data shows)
Root Cause: (the most likely underlying cause, based only on supplied data)
Recommended Solution: (concrete next steps the engineer should take)

If a section has no relevant data, write "Not applicable" for that section
rather than omitting it.
"""


def extract_customer_variants(question: str):
    """
    Returns several candidate search strings for a customer name,
    since names may appear as 'stella.kingori', 'stella kingori',
    or 'stellakingori' depending on how they're stored in RouterOS.

    Any token already containing a '.' (the actual stored username
    format, e.g. 'clarice.ogombo') is treated as its own standalone
    candidate FIRST, regardless of what other words surround it in
    the sentence. This prevents unrelated words in the question
    (e.g. "buffering", "watching", "videos") from being concatenated
    onto the real username and breaking the match — a single merged
    string built from every non-stopword token is fragile against
    any wording not already covered by STOPWORDS.
    """

    tokens = re.findall(r"[a-z0-9.]+", question.lower())
    kept = [t for t in tokens if t not in STOPWORDS]

    variants = set()

    for t in kept:
        if "." in t:
            variants.add(t)
            variants.add(t.replace(".", " "))
            variants.add(t.replace(".", ""))

    joined = " ".join(kept).strip()
    if joined:
        variants.add(joined)
        variants.add(joined.replace(" ", "."))
        variants.add(joined.replace(".", " "))
        variants.add(joined.replace(" ", "").replace(".", ""))

    return [v for v in variants if v]


def summarize_customer_matches(matches):

    summary = {
        "router": None,
        "pppoe_secret": None,
        "pppoe_active": False,
        "pppoe_active_data": None,
        "queues": [],
        "lease": None,
    }

    for m in matches:

        summary["router"] = m.get("router")
        category = m.get("category", "")
        data = m.get("data", {})

        if category == "ppp/secret":
            summary["pppoe_secret"] = data

        elif category == "ppp/active":
            summary["pppoe_active"] = True
            summary["pppoe_active_data"] = data

        elif category == "queue/simple":
            try:
                up_limit, down_limit = [
                    int(x) for x in str(data.get("max-limit", "0/0")).split("/")
                ]
            except Exception:
                up_limit, down_limit = 0, 0

            try:
                up_rate, down_rate = [
                    int(x) for x in str(data.get("rate", "0/0")).split("/")
                ]
            except Exception:
                up_rate, down_rate = 0, 0

            up_util = round((up_rate / up_limit) * 100, 1) if up_limit else 0
            down_util = round((down_rate / down_limit) * 100, 1) if down_limit else 0

            try:
                dropped_up, dropped_down = [
                    int(x) for x in str(data.get("dropped", "0/0")).split("/")
                ]
            except Exception:
                dropped_up, dropped_down = 0, 0
            try:
                packets_up, packets_down = [
                    int(x) for x in str(data.get("packets", "0/0")).split("/")
                ]
            except Exception:
                packets_up, packets_down = 0, 0
            dropped_upload_percent = (
                round((dropped_up / packets_up) * 100, 2) if packets_up else 0
            )
            dropped_download_percent = (
                round((dropped_down / packets_down) * 100, 2) if packets_down else 0
            )

            summary["queues"].append({
                "name": data.get("name") or data.get("comment") or "unnamed",
                "target": data.get("target"),
                "disabled": data.get("disabled"),
                "upload_util_percent": up_util,
                "download_util_percent": down_util,
                "dropped_upload": dropped_up,
                "dropped_download": dropped_down,
                "total_packets_upload": packets_up,
                "total_packets_download": packets_down,
                "dropped_upload_percent": dropped_upload_percent,
                "dropped_download_percent": dropped_download_percent,
            })

        elif category == "ip/dhcp-server/lease":
            summary["lease"] = data

    return summary


class MayaAssistant:

    @staticmethod
    def ask(question: str, history=None):
        try:
            return MayaAssistant._ask_inner(question, history)
        except Exception as e:
            return {
                "assistant": "Maya",
                "answer": f"Something went wrong while processing that request. The error has been logged: {str(e)}"
            }

    @staticmethod
    def _ask_inner(question: str, history=None):

        original_question = question
        question = question.lower()

        routers = MayaMemory.all_routers()

        last_router_mentioned, last_customer_mentioned = resolve_last_mentioned(
            history or [], routers
        )

        router_for_action = None
        for router in routers:
            if router["router"].lower() in question:
                router_for_action = router["router"]
                break

        if not router_for_action and last_router_mentioned and is_pronoun_only(question):
            router_for_action = last_router_mentioned

        # ------------------------------------------------------
        # Website / route reachability diagnostics
        # Triggered by a domain-like token plus intent words such as
        # "why", "access", "reach", "block", "route".
        # ------------------------------------------------------
        domain_match = re.search(
            r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})\b",
            original_question
        )

        route_intent_words = {
            "access", "reach", "block", "blocked",
            "route", "routes", "unreachable", "website", "site",
            "check", "working", "load", "loading", "open",
            "visit", "down", "connect", "connecting"
        }
        has_route_intent = any(w in question for w in route_intent_words)

        if domain_match and has_route_intent:

            target_domain = domain_match.group(1)

            # Only treat this as a website query if it ACTUALLY resolves via
            # DNS. Customer usernames (e.g. 'stella.kingori') can look
            # domain-shaped but won't resolve — fall through to normal
            # customer-query handling instead of hard-failing.
            precheck_ip = resolve_hostname(target_domain) if 'resolve_hostname' in dir() else None

            try:
                from app.routers.mikrotik import resolve_hostname as _resolve_check
                precheck_ip = _resolve_check(target_domain)
            except Exception:
                precheck_ip = None

            if not precheck_ip:
                domain_match = None  # fall through, skip this branch entirely

        if domain_match and has_route_intent:

            try:
                diag = check_website_access(target_domain)
            except Exception as e:
                diag = {"error": str(e)}

            if diag.get("error"):
                return {
                    "assistant": "Maya",
                    "answer": f"Could not complete diagnostics for '{target_domain}': {diag['error']}"
                }

            router_summaries = []
            for router_name, data in diag.get("routers", {}).items():

                route = data.get("route")
                trace = data.get("traceroute", {})
                blocks = data.get("blocking_rules", [])

                hops = trace.get("hops", [])
                hop_summary = f"{len(hops)} hops recorded" if hops else "no traceroute data"

                route_summary = (
                    f"via gateway {route.get('gateway')} (route {route.get('dst_address')})"
                    if route else "no matching route found"
                )

                block_summary = (
                    f"{len(blocks)} matching firewall block rule(s) found: " +
                    "; ".join(f"{b.get('chain')}/{b.get('action')} ({b.get('comment') or 'no comment'})" for b in blocks)
                    if blocks else "no blocking firewall rules found"
                )

                router_summaries.append(
                    f"Router {router_name}: {route_summary}. {hop_summary}. {block_summary}."
                )

            router_text = "\n".join(router_summaries)

            prompt = f"""
You are Maya, the Hyperwave Networks AI Network Operations Center Engineer.

Answer ONLY from the supplied data. Never invent values.
The user is asking about reachability to an external website/domain.

{RESPONSE_STYLE_INSTRUCTIONS}

Target domain: {target_domain}
Resolved IP: {diag.get("resolved_ip")}

Per-router diagnostic results:
{router_text}

If a blocking firewall rule was found on any router, that is very likely
the Root Cause. If no route was found on a router, that router cannot
reach the destination at all. If routes and traceroute look normal and
no blocks were found, the issue is likely outside network control
(e.g. the destination site itself, or DNS).

Question being asked: {original_question}
"""

            answer = ask_llm(prompt)

            return {
                "assistant": "Maya",
                "target": target_domain,
                "resolved_ip": diag.get("resolved_ip"),
                "answer": answer
            }

        # ------------------------------------------------------
        # Explicit IP-based enable/disable
        # ------------------------------------------------------
        ip_pattern = re.search(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", original_question)

        ip_is_unblock = "unblock" in question
        ip_is_block = (not ip_is_unblock) and ("block" in question)

        if ip_pattern and ("disable" in question or "enable" in question or ip_is_block or ip_is_unblock):

            ip_value = ip_pattern.group(0)
            should_disable = ("disable" in question) or ip_is_block

            try:
                result = set_queue_state_by_ip(ip_value, disabled=should_disable)
            except Exception as e:
                result = {"success": False, "message": str(e)}

            if result.get("success"):
                return {
                    "assistant": "Maya",
                    "action": "disabled" if should_disable else "enabled",
                    "router": result.get("router"),
                    "answer": result.get("message")
                }
            else:
                return {
                    "assistant": "Maya",
                    "answer": result.get("message", f"Could not find a queue matching {ip_value}.")
                }

        # ------------------------------------------------------
        # Propose a firewall rule via GitHub PR (draft-and-approve
        # only -- does NOT touch any router directly)
        # ------------------------------------------------------
        if "propose" in question and ("firewall" in question or "ssh" in question):

            if not ip_pattern:
                return {
                    "assistant": "Maya",
                    "answer": "I need an IP address to propose a rule for. Try: 'propose allowing 41.90.1.1 through ssh on kariokor'."
                }

            ip_value = ip_pattern.group(0)

            target_router = None
            for router in routers:
                if router["router"].lower() in question:
                    target_router = router["router"]
                    break

            if not target_router:
                return {
                    "assistant": "Maya",
                    "answer": "Which router should this apply to? e.g. 'propose allowing 41.90.1.1 through ssh on kariokor'."
                }

            if target_router not in ROUTERS or "ssh_port" not in ROUTERS[target_router]:
                return {
                    "assistant": "Maya",
                    "answer": f"I don't have an SSH port configured for '{target_router}', so I can't draft this proposal."
                }

            ssh_port = ROUTERS[target_router]["ssh_port"]
            rule_command = (
                f'/ip firewall filter add chain=input action=accept protocol=tcp '
                f'dst-port={ssh_port} src-address={ip_value} '
                f'comment=\"maya-proposed-ssh-{ip_value}\"'
            )
            reason = f"Requested via Maya chat: allow {ip_value} to reach SSH on {target_router}."

            try:
                result = propose_firewall_rule(target_router, rule_command, reason)
            except Exception as e:
                result = {"success": False, "message": str(e)}

            if result.get("success"):
                return {
                    "assistant": "Maya",
                    "action": "proposed",
                    "router": target_router,
                    "answer": f"I've drafted this as a pull request for review -- nothing has been applied yet: {result.get('pr_url')}"
                }
            else:
                return {
                    "assistant": "Maya",
                    "answer": f"I couldn't draft that proposal: {result.get('message')}"
                }

        # ------------------------------------------------------
        # Human-readable config summary (from the Git-backed
        # .rsc export -- deterministic, no LLM narration)
        # ------------------------------------------------------
        if "config" in question and ("all" in question or "full" in question or "everything" in question or "raw" in question):

            target_router = None
            for router in routers:
                if router["router"].lower() in question:
                    target_router = router["router"]
                    break

            if not target_router:
                return {
                    "assistant": "Maya",
                    "answer": "Which router's full config do you want? e.g. 'show me all of kariokor's config'."
                }

            try:
                result = get_raw_router_config(target_router)
            except Exception as e:
                result = {"success": False, "message": str(e)}

            if result.get("success"):
                return {
                    "assistant": "Maya",
                    "router": target_router,
                    "answer": result.get("content")
                }
            else:
                return {
                    "assistant": "Maya",
                    "answer": result.get("message", f"Could not retrieve config for {target_router}.")
                }

        if "config" in question:

            target_router = None
            for router in routers:
                if router["router"].lower() in question:
                    target_router = router["router"]
                    break

            if not target_router:
                return {
                    "assistant": "Maya",
                    "answer": "Which router's config do you want? e.g. 'show me kincar's config'."
                }

            try:
                section_result = get_config_section(target_router, question)
                if section_result.get("success"):
                    return {
                        "assistant": "Maya",
                        "router": target_router,
                        "answer": f"{section_result.get('section')} ({section_result.get('line_count')} lines):\n\n{section_result.get('content')}"
                    }
                result = summarize_router_config(target_router)
            except Exception as e:
                result = {"success": False, "message": str(e)}

            if result.get("success"):
                return {
                    "assistant": "Maya",
                    "router": target_router,
                    "answer": result.get("summary")
                }
            else:
                return {
                    "assistant": "Maya",
                    "answer": result.get("message", f"Could not summarize config for {target_router}.")
                }

        # ------------------------------------------------------
        # Traffic anomaly questions (spikes / silent interfaces)
        # ------------------------------------------------------
        if router_for_action and (
            "spike" in question or "silent" in question
            or "traffic anomaly" in question or "zero traffic" in question
        ):

            try:
                findings = []
                for iface in _distinct_interfaces(router_for_action):
                    zero = _check_zero_traffic(router_for_action, iface)
                    spike = _check_spike(router_for_action, iface)
                    if zero.get("status") == "silent":
                        findings.append(f"- [WARNING] '{iface}' is running but has shown zero traffic recently despite normally carrying it.")
                    if spike.get("status") == "spiking":
                        findings.append(f"- [WARNING] '{iface}' is at {spike.get('ratio')}x its baseline {spike.get('direction')} throughput.")
            except Exception as e:
                return {
                    "assistant": "Maya",
                    "router": router_for_action,
                    "answer": f"Could not check traffic anomalies on {router_for_action}: {str(e)}"
                }

            if findings:
                answer = f"Traffic anomalies on {router_for_action}:\n" + "\n".join(findings)
            else:
                answer = f"No traffic spikes or silent interfaces detected on {router_for_action} right now."

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": answer
            }

        # ------------------------------------------------------
        # PPP anomaly questions (flapping / mass disconnect) —
        # placed BEFORE the disconnect-action branch so phrases like
        # "mass disconnects" aren't misread as a kill-session command.
        # ------------------------------------------------------
        if router_for_action and (
            "flap" in question or "flapping" in question or "mass disconnect" in question
        ):

            try:
                flapping = _check_flapping(router_for_action)
                mass = _check_mass_disconnect(router_for_action)
            except Exception as e:
                return {
                    "assistant": "Maya",
                    "router": router_for_action,
                    "answer": f"Could not check PPP anomalies on {router_for_action}: {str(e)}"
                }

            lines = []
            for f in flapping:
                lines.append(
                    f"- [{f['severity']}] '{f['username']}' dropped {f['count']} times in the last 10 minutes."
                )
            if mass.get("status") == "mass_disconnect":
                lines.append(
                    f"- [CRITICAL] Mass disconnect: {mass['distinct_customers']} distinct customers dropped in the last 5 minutes."
                )

            if lines:
                answer = f"PPP anomalies on {router_for_action}:\n" + "\n".join(lines)
            else:
                answer = f"No flapping customers or mass disconnects detected on {router_for_action} right now."

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": answer,
                "raw": {"flapping": flapping, "mass_disconnect": mass}
            }

        # ------------------------------------------------------
        # Explicit DISCONNECT action (kills active session only,
        # does not disable the account — use "block" for that)
        # ------------------------------------------------------
        if "disconnect" in question:

            variants = extract_customer_variants(question)

            for v in variants:
                if not v:
                    continue

                for router in routers:
                    router_name = router["router"]

                    try:
                        result = disconnect_pppoe(router_name, v)
                    except Exception as e:
                        result = {"success": False, "message": str(e)}

                    if result.get("success"):
                        return {
                            "assistant": "Maya",
                            "action": "disconnected",
                            "router": router_name,
                            "answer": f"{result.get('customer')} has been disconnected on router {router_name}. {result.get('message', '')}"
                        }

            return {
                "assistant": "Maya",
                "answer": "I could not find a matching active session to disconnect. Please confirm the exact customer name."
            }

        # ------------------------------------------------------
        # Explicit RECONNECT action
        # ------------------------------------------------------
        if "reconnect" in question:

            variants = extract_customer_variants(question)
            if is_pronoun_only(question) and last_customer_mentioned:
                variants = [last_customer_mentioned] + variants

            # First, find which router this customer actually belongs to —
            # try a live search, then fall back to last-seen history.
            target_router = None
            matched_name = None

            for v in variants:
                if not v:
                    continue
                try:
                    m = UniversalSearch.search(v)
                except Exception:
                    m = []
                m = [x for x in m if x.get("data")]
                if m:
                    target_router = m[0]["router"]
                    matched_name = v
                    break

            if not target_router:
                for v in variants:
                    if not v:
                        continue
                    try:
                        records = MayaMemory.search_last_seen(v)
                    except Exception:
                        records = []
                    if records:
                        target_router = records[0]["router"]
                        matched_name = v
                        break

            if not target_router:
                return {
                    "assistant": "Maya",
                    "answer": "I could not find a matching customer to reconnect. Please confirm the exact customer name."
                }

            try:
                result = reconnect_customer(target_router, matched_name)
            except Exception as e:
                result = {"success": False, "message": str(e)}

            return {
                "assistant": "Maya",
                "action": "reconnect_attempted",
                "router": target_router,
                "answer": result.get("message")
            }

        # ------------------------------------------------------
        # Explicit RESET (PPP session) action
        # ------------------------------------------------------
        if "reset" in question and ("ppp" in question or "session" in question):

            variants = extract_customer_variants(question)
            if is_pronoun_only(question) and last_customer_mentioned:
                variants = [last_customer_mentioned] + variants

            for v in variants:
                if not v:
                    continue

                for router in routers:
                    router_name = router["router"]

                    try:
                        result = reset_ppp_session(router_name, v)
                    except Exception as e:
                        result = {"success": False, "message": str(e)}

                    if result.get("success"):
                        return {
                            "assistant": "Maya",
                            "action": "session_reset",
                            "router": router_name,
                            "answer": result.get("message")
                        }

            return {
                "assistant": "Maya",
                "answer": "I could not find a matching active session to reset. Please confirm the exact customer name."
            }

        # ------------------------------------------------------
        # Explicit RESTART INTERFACE action
        # ------------------------------------------------------
        if "restart" in question and router_for_action:

            iface_match = re.search(
                r"\b(ether\d+|wlan\d+|bridge\d+|vlan[\w-]*|sfp\d*[\w-]*|pppoe-\w+)\b",
                question
            )

            if iface_match:
                iface_name = iface_match.group(1)

                try:
                    result = restart_interface(router_for_action, iface_name)
                except Exception as e:
                    result = {"success": False, "message": str(e)}

                return {
                    "assistant": "Maya",
                    "action": "interface_restart_attempted",
                    "router": router_for_action,
                    "answer": result.get("message")
                }
            else:
                return {
                    "assistant": "Maya",
                    "answer": f"I found router '{router_for_action}' but couldn't identify which interface to restart. Please specify the interface name (e.g. 'restart ether1 on {router_for_action}')."
                }

        # ------------------------------------------------------
        # Explicit BACKUP action
        # ------------------------------------------------------
        if "backup" in question:

            if "all" in question:
                try:
                    results = backup_all_routers()
                except Exception as e:
                    results = [{"success": False, "message": str(e)}]

                summary = "; ".join(
                    r.get("message", "unknown result") for r in results
                )
                return {
                    "assistant": "Maya",
                    "action": "backup_all",
                    "answer": f"Backup attempted on all routers. {summary}"
                }

            elif router_for_action:
                try:
                    result = backup_router(router_for_action)
                except Exception as e:
                    result = {"success": False, "message": str(e)}

                return {
                    "assistant": "Maya",
                    "action": "backup",
                    "router": router_for_action,
                    "answer": result.get("message")
                }

            else:
                return {
                    "assistant": "Maya",
                    "answer": "Please specify which router to back up, or say 'backup all routers'."
                }

        # ------------------------------------------------------
        # Explicit BLOCK / UNBLOCK actions
        # ------------------------------------------------------
        is_unblock = "unblock" in question
        is_block = (not is_unblock) and ("block" in question)

        if is_block or is_unblock:

            variants = extract_customer_variants(question)

            for v in variants:
                if not v:
                    continue

                for router in routers:
                    router_name = router["router"]

                    try:
                        if is_unblock:
                            result = unblock_customer(router_name, v)
                        else:
                            result = block_customer(router_name, v)
                    except Exception as e:
                        result = {"success": False, "message": str(e)}

                    if result.get("success"):
                        action = "unblocked" if is_unblock else "blocked"
                        return {
                            "assistant": "Maya",
                            "action": action,
                            "router": router_name,
                            "answer": f"{result.get('customer')} has been {action} on router {router_name}. {result.get('message')}"
                        }

            action = "unblock" if is_unblock else "block"
            return {
                "assistant": "Maya",
                "answer": f"I could not find a matching customer to {action}. Please confirm the exact customer name."
            }

        # ------------------------------------------------------
        # Explicit SCAN / INCIDENTS actions (router-level, require
        # a recognizable router name in the question)
        # ------------------------------------------------------
        if router_for_action and "scan" in question:

            try:
                result = IncidentEngine.check_router(router_for_action)
            except Exception as e:
                result = {"error": str(e)}

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": (
                    f"Scan complete for {router_for_action}. "
                    f"CPU: {result.get('cpu_load', 'Unknown')}%, "
                    f"Memory: {result.get('memory_percent', 'Unknown')}%, "
                    f"New incidents found: {result.get('incident_count', 0)}."
                ),
                "raw": result
            }

        if router_for_action and ("incident" in question):

            try:
                history = IncidentEngine.history(router_for_action)
            except Exception as e:
                history = []

            if not history:
                return {
                    "assistant": "Maya",
                    "router": router_for_action,
                    "answer": f"No incidents found on record for {router_for_action}."
                }

            lines = []
            for h in history[:10]:
                lines.append(
                    f"- [{h.get('severity')}] {h.get('title')} — {h.get('description')} ({h.get('created_at')})"
                )

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": "Recent incidents:\n" + "\n".join(lines)
            }

        # ------------------------------------------------------
        # Explicit SECURITY POSTURE action
        # ------------------------------------------------------
        if router_for_action and ("posture" in question or "security" in question):

            try:
                posture_result = {
                    "services": _check_exposed_services(router_for_action),
                    "default_admin": _check_default_admin(router_for_action),
                    "full_group_users": _check_full_group_users(router_for_action),
                    "firewall_input": _check_firewall_input_chain(router_for_action),
                    "routeros_version": _check_routeros_version(router_for_action),
                }
            except Exception as e:
                return {
                    "assistant": "Maya",
                    "router": router_for_action,
                    "answer": f"Could not run a posture scan on {router_for_action}: {str(e)}"
                }

            lines = []
            for svc in posture_result.get("services", []):
                if svc.get("status") == "exposed":
                    lines.append(f"- [{svc.get('severity')}] Service '{svc['service']}' is exposed with no address restriction.")
            da = posture_result.get("default_admin", {})
            if da.get("status") == "present":
                lines.append("- [WARNING] Default 'admin' account is still enabled.")
            fg = posture_result.get("full_group_users", {})
            if fg.get("status") == "excess":
                lines.append(f"- [WARNING] Extra full-privilege accounts: {', '.join(fg.get('users', []))}.")
            fi = posture_result.get("firewall_input", {})
            if fi.get("status") == "open":
                lines.append("- [CRITICAL] No catch-all drop rule on the firewall input chain.")
            rv = posture_result.get("routeros_version", {})
            if rv.get("status") == "outdated":
                lines.append(f"- [WARNING] RouterOS update available: {rv.get('installed')} -> {rv.get('latest')}.")

            if lines:
                answer = f"Security posture findings for {router_for_action}:\n" + "\n".join(lines)
            else:
                answer = f"Security posture for {router_for_action} looks clean — no issues found across services, admin accounts, firewall input chain, or RouterOS version."

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": answer,
                "raw": posture_result
            }

        # ------------------------------------------------------
        # Router LOGS request — returns recent raw log lines,
        # filtered to drop noisy 'maya-ai via api' polling entries
        # from our own scheduled collectors.
        # ------------------------------------------------------
        if router_for_action and ("log" in question or "logs" in question):

            try:
                log_result = get_logs(router_for_action)
            except Exception as e:
                return {
                    "assistant": "Maya",
                    "router": router_for_action,
                    "answer": f"Could not retrieve logs for {router_for_action}: {str(e)}"
                }

            all_logs = log_result.get("logs", [])

            filtered = [
                l for l in all_logs
                if "maya-ai" not in (l.get("message") or "").lower()
            ]

            recent = filtered[-20:] if len(filtered) > 20 else filtered

            if not recent:
                answer = f"No recent log entries found for {router_for_action} (excluding routine API polling)."
            else:
                lines = [
                    f"[{l.get('time')}] ({l.get('topics')}) {l.get('message')}"
                    for l in recent
                ]
                answer = f"Recent log entries for {router_for_action}:\n" + "\n".join(lines)

            return {
                "assistant": "Maya",
                "router": router_for_action,
                "answer": answer
            }

        # ------------------------------------------------------
        # Router-specific status/health questions
        # ------------------------------------------------------
        selected_router = None

        for alias, real_name in ROUTER_ALIASES.items():
            if alias in question:
                for router in routers:
                    if router["router"].lower() == real_name.lower():
                        selected_router = router["router"]
                        break
            if selected_router:
                break

        if not selected_router:
            for router in routers:
                if router["router"].lower() in question:
                    selected_router = router["router"]
                    break

        if not selected_router and last_router_mentioned and is_pronoun_only(question):
            selected_router = last_router_mentioned

        if selected_router:

            report = MayaRecommendations.recommend(selected_router)

            telemetry = report["context"].get("telemetry", {}) or {}
            inventory = report["context"].get("inventory", {}) or {}
            incidents = report["context"].get("incidents", []) or []
            interfaces = report["context"].get("interfaces", []) or []
            pppoe_sessions = report["context"].get("pppoe_sessions", []) or []
            queues = report["context"].get("queues", []) or []

            queue_lines = []
            for q in queues[:10]:
                try:
                    up_limit, down_limit = [int(x) for x in q.get("max_limit", "0/0").split("/")]
                except Exception:
                    up_limit, down_limit = 0, 0

                up_rate = q.get("upload_rate") or 0
                down_rate = q.get("download_rate") or 0

                up_util = round((up_rate / up_limit) * 100, 1) if up_limit else 0
                down_util = round((down_rate / down_limit) * 100, 1) if down_limit else 0

                dropped = (q.get("upload_dropped") or 0) + (q.get("download_dropped") or 0)

                queue_lines.append(
                    f"- {q.get('queue_name')}: upload {up_util}% of limit, "
                    f"download {down_util}% of limit, dropped packets: {dropped}"
                )

            queue_summary = "\n".join(queue_lines) if queue_lines else "No queue data available."

            traffic_lines = []
            for iface in interfaces[:15]:
                rx_mbps = round((iface.get("rx_rate") or 0) / 1_000_000, 2)
                tx_mbps = round((iface.get("tx_rate") or 0) / 1_000_000, 2)
                if rx_mbps > 0 or tx_mbps > 0:
                    traffic_lines.append(
                        f"- {iface.get('interface_name')}: RX {rx_mbps} Mbps, TX {tx_mbps} Mbps, running={bool(iface.get('running'))}"
                    )
            traffic_summary = "\n".join(traffic_lines) if traffic_lines else "No active traffic detected on any interface."

            diagnosis_lines = "\n".join(
                f"- [{d.get('status')}] {d.get('component')}: {d.get('message')}"
                for d in report.get("diagnosis", [])
            ) or "No diagnosis flags."

            recommendation_lines = "\n".join(
                f"- {r}" for r in report.get("recommendations", [])
            ) or "No specific recommendations."

            prompt = f"""
You are Maya, the Hyperwave Networks AI Network Operations Center Engineer.

Answer ONLY from the supplied data.
Never invent values.
If data is missing, clearly state it.
If the user asks why something is slow, prioritize Queue/Bandwidth data
and PPPoE session count over CPU/Memory/Temperature, since congestion is
the most common cause of slowness even when system health is normal.

{RESPONSE_STYLE_INSTRUCTIONS}

Router: {selected_router}
Identity: {inventory.get("identity","Unknown")}

Telemetry
CPU: {telemetry.get("cpu_load","Unknown")}%
Memory Used: {telemetry.get("memory_used","Unknown")}
Memory Total: {telemetry.get("memory_total","Unknown")}
Temperature: {telemetry.get("temperature","Unknown")}°C

Active PPPoE Sessions: {len(pppoe_sessions)}
Interface Count: {len(interfaces)}

Queue / Bandwidth Utilization:
{queue_summary}

Live Interface Traffic (bits per second, converted to Mbps):
{traffic_summary}

Open Incidents: {len(incidents)}

Diagnosis:
{diagnosis_lines}

Recommendations:
{recommendation_lines}

Question being asked: {original_question}
"""

            answer = ask_llm(prompt)

            return {
                "assistant": "Maya",
                "router": selected_router,
                "answer": answer
            }

        # ------------------------------------------------------
        # Show routers with issues
        # ------------------------------------------------------
        if "problem" in question or "issue" in question:
            unhealthy = []
            for router in routers:
                if router["summary"]["open_incidents"] > 0:
                    unhealthy.append({
                        "router": router["router"],
                        "incidents": router["summary"]["open_incidents"]
                    })
            return {
                "assistant": "Maya",
                "answer": unhealthy
            }

        # ------------------------------------------------------
        # List routers
        # ------------------------------------------------------
        if "router" in question and "customer" not in question:
            return {
                "assistant": "Maya",
                "routers": [r["router"] for r in routers]
            }

        # ------------------------------------------------------
        # Customer-level questions
        # ------------------------------------------------------
        variants = extract_customer_variants(question)

        if is_pronoun_only(question) and last_customer_mentioned:
            variants = [last_customer_mentioned] + variants

        status_keywords = {
            "online", "offline", "slow", "status", "reachable",
            "ping", "up", "down", "healthy", "unhealthy", "working"
        }
        is_status_question = any(k in question for k in status_keywords)

        matches = []
        matched_query = None

        for v in variants:
            try:
                m = UniversalSearch.search(v)
            except Exception:
                m = []
            m = [x for x in m if x.get("data")]
            if m:
                matches = m
                matched_query = v
                break

        # No live match — check persistent last-seen history before giving up
        if not matches and variants and is_status_question:

            last_seen_records = []
            for v in variants:
                try:
                    records = MayaMemory.search_last_seen(v)
                except Exception:
                    records = []
                if records:
                    last_seen_records = records
                    matched_query = v
                    break

            if last_seen_records:

                record = last_seen_records[0]
                router_name = record.get("router")

                open_incidents = []
                for router in routers:
                    if router["router"] == router_name:
                        open_incidents = router.get("incidents", []) or []
                        break

                if open_incidents:
                    incident_lines = "\n".join(
                        f"  - [{inc.get('severity')}] {inc.get('category')}: {inc.get('title')} — {inc.get('description')} (since {inc.get('created_at')})"
                        for inc in open_incidents[:5]
                    )
                    incident_text = f"{len(open_incidents)} open incident(s) on {router_name}:\n{incident_lines}"
                else:
                    incident_text = f"No open incidents currently logged for {router_name}."

                # Compute exact offline duration in Python rather than
                # trusting the LLM to do date arithmetic reliably.
                offline_duration_text = "Unknown"
                try:
                    from datetime import datetime as _dt
                    last_seen_dt = _dt.fromisoformat(record.get("last_seen_at"))
                    delta = _dt.now() - last_seen_dt
                    total_seconds = int(delta.total_seconds())
                    hours, remainder = divmod(total_seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    if hours > 0:
                        offline_duration_text = f"{hours}h {minutes}m {seconds}s"
                    elif minutes > 0:
                        offline_duration_text = f"{minutes}m {seconds}s"
                    else:
                        offline_duration_text = f"{seconds}s"
                except Exception:
                    pass

                # Check if OTHER customers on the same router also dropped
                # recently — correlates isolated vs shared outage.
                recent_drops_same_router = 0
                try:
                    from app.database.database import db as _db
                    recent_rows = _db.fetchall(
                        """
                        SELECT COUNT(*) as cnt FROM incidents
                        WHERE router=? AND category='PPP_FAILURE'
                        AND created_at >= datetime('now', '-15 minutes')
                        """,
                        (router_name,)
                    )
                    recent_drops_same_router = recent_rows[0]["cnt"] if recent_rows else 0
                except Exception:
                    recent_drops_same_router = 0

                correlation_text = (
                    f"{recent_drops_same_router} other customer session(s) on {router_name} also dropped in the last 15 minutes — possible shared outage."
                    if recent_drops_same_router > 1 else
                    f"No other customer drops on {router_name} in the last 15 minutes — appears isolated to this customer."
                )

                prompt = f"""
You are Maya, the Hyperwave Networks AI Network Operations Center Engineer.

Answer ONLY from the supplied data. Never invent values.
This customer has NO live/active session right now — they appear OFFLINE.
Use the last-known data below to explain the situation and give the
engineer clear, practical troubleshooting steps. Do not speculate about
domains, companies, or anything unrelated to ISP network troubleshooting.

{RESPONSE_STYLE_INSTRUCTIONS}

Matched customer: {matched_query}
Last known router: {router_name}
Exact last known IP: {record.get("last_ip") or "Unknown"}
Session duration before disconnect: {record.get("last_uptime") or "Unknown"}
Last seen at (timestamp): {record.get("last_seen_at") or "Unknown"}
Time since offline (computed): {offline_duration_text}
Outage correlation: {correlation_text}
Router incident status:
{incident_text}

Troubleshooting checklist to draw from for the Recommended Solution section:
1. Check power to the customer's ONU/router/CPE device.
2. Check the physical fiber/cable connection for damage or disconnection.
3. Check RADIUS/PPPoE authentication logs on {router_name} for failed login attempts from this customer.
4. Check whether other customers on the same router or queue are also currently offline (suggests a shared outage rather than an isolated customer issue).
5. If the last-seen timestamp is very recent (minutes), this may be a brief drop — advise waiting briefly before escalating. If it has been offline for hours or longer, treat it as an active fault requiring field investigation.

Question being asked: {original_question}
"""

                answer = ask_llm(prompt)

                return {
                    "assistant": "Maya",
                    "customer_query": matched_query,
                    "status": "OFFLINE",
                    "answer": answer
                }

            else:
                return {
                    "assistant": "Maya",
                    "customer_query": variants[0] if variants else question,
                    "answer": f"I have no record of a customer matching '{variants[0] if variants else question}' — neither a live session nor any historical last-seen data. Please confirm the exact customer name or username."
                }

        if matches:

            summary = summarize_customer_matches(matches)

            active_data = summary.get("pppoe_active_data") or {}
            lease = summary.get("lease") or {}
            secret = summary.get("pppoe_secret") or {}

            client_name = (
                active_data.get("name")
                or secret.get("name")
                or matched_query
            )

            client_ip = active_data.get("address") or lease.get("address")
            uptime = active_data.get("uptime")

            health_check = analyze_customer({
                "query": matched_query,
                "router": summary["router"],
                "pppoe": active_data if summary.get("pppoe_active") else None,
                "pppoe_secret": secret,
                "queue": summary["queues"][0] if summary["queues"] else None,
                "lease": lease if lease else None,
            })
            print(f"[DEBUG health_check] matched_query={matched_query!r} router={summary['router']!r} => {health_check}")

            ping_result = None
            if client_ip:
                try:
                    ping_result = ping_host(summary["router"], client_ip)
                except Exception as e:
                    ping_result = {"reachable": False, "error": str(e)}

            queue_text_lines = []
            for q in summary["queues"]:
                queue_text_lines.append(
                    f"- {q['name']} (target {q['target']}, disabled={q['disabled']}): "
                    f"upload {q['upload_util_percent']}% of limit, "
                    f"download {q['download_util_percent']}% of limit, "
                    f"dropped upload={q['dropped_upload']} of {q['total_packets_upload']} total packets "
                    f"({q['dropped_upload_percent']}%), "
                    f"dropped download={q['dropped_download']} of {q['total_packets_download']} total packets "
                    f"({q['dropped_download_percent']}%)"
                )
            queue_text = "\n".join(queue_text_lines) if queue_text_lines else "No queue data found."
            queue_text += (
                "\n\nNote: these packet/drop counters are cumulative totals since the "
                "queue was last reset (not a live rate). Judge severity using the "
                "percentage figures above, not the raw counts. As a rough guide: "
                "under ~0.5% dropped is typically negligible, ~0.5-2% may cause "
                "noticeable but mild degradation, and above ~2% is a strong signal "
                "of real congestion or a queue/link problem worth investigating."
            )

            if ping_result is None:
                ping_text = "No IP address available for this customer, so a live ping could not be performed."
            elif ping_result.get("error"):
                ping_text = f"Ping failed: {ping_result['error']}"
            else:
                ping_text = (
                    f"Reachable: {ping_result['reachable']}, "
                    f"Packet Loss: {ping_result['packet_loss_percent']}%, "
                    f"Avg RTT: {ping_result['avg_rtt_ms']}ms, "
                    f"Min/Max RTT: {ping_result.get('min_rtt_ms')}ms / {ping_result.get('max_rtt_ms')}ms, "
                    f"Jitter: {ping_result.get('jitter_ms')}ms "
                    f"(sent {ping_result['sent']}, received {ping_result['received']})"
                )

            prompt = f"""
You are Maya, the Hyperwave Networks AI Network Operations Center Engineer.

Answer ONLY from the supplied data.
Never invent values.
If data is missing, clearly state it.
The user is asking about a specific CUSTOMER, not a router.

If the ping shows Reachable: True, the customer IS online.
If Reachable: False, state clearly that the customer appears OFFLINE,
even if a PPPoE secret or queue exists for them.
If asked why they are slow, prioritize queue bandwidth utilization and
the dropped-packet PERCENTAGE (not the raw count, which is cumulative
since last reset and not meaningful on its own). Even if ping shows no
packet loss, a meaningfully high dropped-packet percentage on the queue
indicates real degradation the customer would notice — do not conclude
"not slow" purely from ping success. Conversely, do not treat a large
raw dropped-packet count as alarming if the percentage it represents is
low; judge severity from the percentage using the guidance provided with
the queue data.

{RESPONSE_STYLE_INSTRUCTIONS}

For the Recommended Solution section, consider (as applicable):
- If dropped packets are high: check for wireless interference/signal
  strength if this is a wireless link, check physical cable/port for
  CRC errors, compare against other customers on the same parent queue
  to determine if it's isolated or shared infrastructure.
- If queue max-limit seems low relative to complaints: confirm the
  customer's plan matches their configured limit.
- If router CPU was elevated recently: transient spikes can cause drops
  even if a snapshot looks normal — recommend monitoring over time.

If the customer is asking about BUFFERING specifically (video/streaming
stalling or pausing), note that buffering is usually caused by JITTER
(inconsistent latency between packets) or intermittent packet loss —
NOT high average latency or low bandwidth alone. A customer can have a
fast connection with a good average ping and still experience buffering
if latency is inconsistent. Use the Jitter and Min/Max RTT figures in
the ping data as the primary signal:
- Jitter roughly under ~10ms: unlikely to be the cause of buffering.
- Jitter roughly 10-30ms: may cause occasional buffering, worth monitoring.
- Jitter above ~30ms, or a large gap between Min and Max RTT: a strong
  buffering signal — investigate further even if average RTT looks fine.
Additional buffering-specific checks to recommend:
- Ask if buffering happens on Wi-Fi and wired devices equally, or only
  Wi-Fi — if only Wi-Fi, the issue is likely local to the customer's
  home network (signal strength, interference, router placement), not
  the ISP link.
- Ask if buffering happens at specific times of day (e.g. evenings) —
  this points to peak-hour congestion on a shared queue/parent link
  rather than a fault specific to this customer.
- Ask if buffering is specific to one streaming service — this can
  indicate a DNS, CDN routing, or peering issue upstream rather than a
  problem on this network, which is outside what router data can show.

AUTHORITATIVE HEALTH CHECK (deterministic, rule-based — treat this as
ground truth for the customer's overall status; your narrative and
Root Cause/Recommended Solution should be CONSISTENT with this, not
contradict it):
Status: {health_check["status"]}
Health Score: {health_check["health_score"]}/100
Issues Detected: {", ".join(health_check["issues"]) if health_check["issues"] else "None"}
Suggested Actions: {health_check["recommendation"]}

Matched search term: {matched_query}
Client Name: {client_name}
Router: {summary["router"]}
Client IP: {client_ip or "Unknown"}
PPPoE Session Uptime: {uptime or "Unknown"}
Live Ping Result: {ping_text}

Queue Data:
{queue_text}

Question being asked: {original_question}
"""

            answer = ask_llm(prompt)

            # Guard rail: the LLM (a small local model) has been observed
            # to occasionally contradict the deterministic health_check
            # data it was given — e.g. claiming "not flapping" when the
            # data clearly shows it is. Rather than trust the model's
            # prose for the headline status, prepend a code-generated,
            # guaranteed-accurate status line ahead of the LLM's narrative
            # so the correct answer is always visible first regardless of
            # what the model says underneath.
            verified_status_line = (
                f"Verified Status: {health_check['status']} "
                f"(health score {health_check['health_score']}/100)"
            )
            if health_check["status"] == "FLAPPING":
                verified_status_line += (
                    f" — {health_check['checks'].get('stability', '')}. "
                    "This is an instability issue, not a simple up/down state."
                )
            answer = f"{verified_status_line}\n\n{answer}"

            return {
                "assistant": "Maya",
                "customer_query": matched_query,
                "verified_status": health_check["status"],
                "answer": answer
            }

        # ------------------------------------------------------
        # General AI questions
        # ------------------------------------------------------
        answer = ask_llm(original_question)
        return {
            "assistant": "Maya",
            "answer": answer
        }
