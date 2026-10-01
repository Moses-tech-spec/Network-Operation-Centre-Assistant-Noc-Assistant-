import os
import subprocess
from datetime import datetime
import paramiko
from app.config import ROUTERS

BACKUP_DIR = "/app/router-configs"  # /app is the bind-mounted path inside the container; this maps to /opt/network-api/router-configs on the host


def _ssh_client(router_name):
    router = ROUTERS[router_name]
    port = router.get("ssh_port", 22)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=router["host"],
        port=port,
        username=router["username"],
        password=router["password"],
        timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def export_router_config(router_name):
    if router_name not in ROUTERS:
        return {"success": False, "router": router_name, "message": f"Router '{router_name}' not found."}

    try:
        client = _ssh_client(router_name)
    except Exception as e:
        return {"success": False, "router": router_name, "message": f"SSH connection failed: {str(e)}"}

    try:
        stdin, stdout, stderr = client.exec_command("/export", timeout=30)
        output = stdout.read().decode("utf-8", errors="replace")
        error_output = stderr.read().decode("utf-8", errors="replace")
    except Exception as e:
        client.close()
        return {"success": False, "router": router_name, "message": f"Export command failed: {str(e)}"}

    client.close()

    if not output.strip():
        return {
            "success": False,
            "router": router_name,
            "message": f"Export returned no output. stderr: {error_output.strip() or 'none'}"
        }

    os.makedirs(BACKUP_DIR, exist_ok=True)
    filepath = os.path.join(BACKUP_DIR, f"{router_name}.rsc")

    with open(filepath, "w") as f:
        f.write(output)

    return {
        "success": True,
        "router": router_name,
        "filepath": filepath,
        "bytes_written": len(output),
        "message": f"Config exported from {router_name} and written to {filepath}."
    }


def export_all_router_configs():
    results = []
    for router_name in ROUTERS:
        results.append(export_router_config(router_name))
    return results


def commit_config_backups():
    export_results = export_all_router_configs()

    failed = [r for r in export_results if not r.get("success")]
    if len(failed) == len(export_results):
        return {
            "success": False,
            "message": "All router exports failed — skipping git commit.",
            "export_results": export_results,
        }

    try:
        subprocess.run(["git", "add", "."], cwd=BACKUP_DIR, check=True, capture_output=True)

        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=BACKUP_DIR, check=True, capture_output=True, text=True
        )

        if not status.stdout.strip():
            return {
                "success": True,
                "message": "No config changes since last backup — nothing to commit.",
                "export_results": export_results,
            }

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subprocess.run(
            ["git", "commit", "-m", f"Router config backup: {timestamp}"],
            cwd=BACKUP_DIR, check=True, capture_output=True,
        )

    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"Git operation failed: {e.stderr.decode() if e.stderr else str(e)}",
            "export_results": export_results,
        }

    return {
        "success": True,
        "message": "Config backups committed to git.",
        "export_results": export_results,
    }


# ==========================================================
# PROPOSE FIREWALL RULE (draft-and-approve, not auto-applied)
# ==========================================================

import requests
import base64
import json

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # e.g. "Moses-tech-spec/hyper-router-configs"
GITHUB_API = "https://api.github.com"


def _github_headers():
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }


def propose_firewall_rule(router_name, rule_command, reason):
    """
    Does NOT apply anything to the router. Instead, writes the proposed
    RouterOS command to a new branch/file and opens a GitHub PR for
    human review. Only merging the PR (a separate, manual step) should
    trigger actual application later.
    """

    if not GITHUB_TOKEN or not GITHUB_REPO:
        return {"success": False, "message": "GITHUB_TOKEN or GITHUB_REPO not configured in .env"}

    if router_name not in ROUTERS:
        return {"success": False, "message": f"Router '{router_name}' not found."}

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    branch_name = f"propose-{router_name}-{timestamp}"
    file_path = f"proposed-changes/{router_name}-{timestamp}.rsc"

    file_content = (
        f"# Proposed change for {router_name}\n"
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Reason: {reason}\n"
        f"#\n"
        f"# Review this command carefully before merging.\n"
        f"# Merging this PR does NOT automatically apply it (yet) --\n"
        f"# manual application on the router is still required.\n"
        f"\n"
        f"{rule_command}\n"
    )

    try:
        ref_resp = requests.get(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/git/ref/heads/main",
            headers=_github_headers(), timeout=15
        )
        ref_resp.raise_for_status()
        base_sha = ref_resp.json()["object"]["sha"]

        branch_resp = requests.post(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/git/refs",
            headers=_github_headers(),
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            timeout=15
        )
        branch_resp.raise_for_status()

        content_b64 = base64.b64encode(file_content.encode("utf-8")).decode("utf-8")
        file_resp = requests.put(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{file_path}",
            headers=_github_headers(),
            json={
                "message": f"Propose change for {router_name}: {reason}",
                "content": content_b64,
                "branch": branch_name,
            },
            timeout=15
        )
        file_resp.raise_for_status()

        pr_resp = requests.post(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/pulls",
            headers=_github_headers(),
            json={
                "title": f"[Proposed] {router_name}: {reason}",
                "head": branch_name,
                "base": "main",
                "body": (
                    f"**Router:** {router_name}\n\n"
                    f"**Reason:** {reason}\n\n"
                    f"**Proposed command:**\n```\n{rule_command}\n```\n\n"
                    f"This change has **not** been applied. Review and merge to approve; "
                    f"application to the live router is a separate manual step."
                ),
            },
            timeout=15
        )
        pr_resp.raise_for_status()
        pr_data = pr_resp.json()

    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"GitHub API error: {str(e)}"}

    return {
        "success": True,
        "router": router_name,
        "pr_url": pr_data.get("html_url"),
        "pr_number": pr_data.get("number"),
        "branch": branch_name,
        "message": f"Proposed change opened as PR #{pr_data.get('number')}: {pr_data.get('html_url')}"
    }


# ==========================================================
# APPLY MERGED PROPOSALS (the actual "merge triggers apply" step)
# ==========================================================

def _get_pr_files(pr_number):
    resp = requests.get(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/pulls/{pr_number}/files",
        headers=_github_headers(), timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def _get_pr_comments(pr_number):
    resp = requests.get(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/issues/{pr_number}/comments",
        headers=_github_headers(), timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def _already_applied(pr_number):
    comments = _get_pr_comments(pr_number)
    return any(c.get("body", "").startswith("[OK] Applied") or c.get("body", "").startswith("[FAILED] Apply failed")
               for c in comments)


def _post_pr_comment(pr_number, body):
    requests.post(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/issues/{pr_number}/comments",
        headers=_github_headers(),
        json={"body": body},
        timeout=15
    )


def _extract_router_and_command(file_entry):
    filename = file_entry["filename"]
    base = filename.split("/")[-1]
    router_name = base.split("-")[0]

    content_resp = requests.get(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{filename}",
        headers=_github_headers(),
        params={"ref": "main"},
        timeout=15
    )
    content_resp.raise_for_status()
    raw = base64.b64decode(content_resp.json()["content"]).decode("utf-8")

    commands = [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    return router_name, commands


def apply_merged_proposals():
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return {"success": False, "message": "GITHUB_TOKEN or GITHUB_REPO not configured in .env"}

    resp = requests.get(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/pulls",
        headers=_github_headers(),
        params={"state": "closed", "base": "main", "per_page": 50},
        timeout=15
    )
    resp.raise_for_status()
    closed_prs = resp.json()

    results = []

    for pr in closed_prs:
        if not pr.get("merged_at"):
            continue

        pr_number = pr["number"]

        try:
            files = _get_pr_files(pr_number)
        except requests.exceptions.RequestException as e:
            results.append({"pr": pr_number, "status": "error", "message": f"Could not fetch files: {e}"})
            continue

        touches_proposal = any(f["filename"].startswith("proposed-changes/") for f in files)
        if not touches_proposal:
            continue

        if _already_applied(pr_number):
            continue

        proposal_file = next(f for f in files if f["filename"].startswith("proposed-changes/"))

        try:
            router_name, commands = _extract_router_and_command(proposal_file)
        except Exception as e:
            _post_pr_comment(pr_number, f"[FAILED] Apply failed: could not read proposal file: {e}")
            results.append({"pr": pr_number, "status": "error", "message": str(e)})
            continue

        if router_name not in ROUTERS or not commands:
            _post_pr_comment(pr_number, f"[FAILED] Apply failed: router '{router_name}' unknown or no command found.")
            results.append({"pr": pr_number, "status": "error", "message": "unknown router or empty command"})
            continue

        try:
            client = _ssh_client(router_name)
            outputs = []
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                outputs.append(f"$ {cmd}\n{out}{err}".strip())
            client.close()

            summary = "\n\n".join(outputs) or "(no output -- command likely succeeded silently)"
            _post_pr_comment(pr_number, f"[OK] Applied to {router_name}.\n\n```\n{summary}\n```")
            results.append({"pr": pr_number, "router": router_name, "status": "applied"})

        except Exception as e:
            _post_pr_comment(pr_number, f"[FAILED] Apply failed on {router_name}: {e}")
            results.append({"pr": pr_number, "router": router_name, "status": "error", "message": str(e)})

    return {"success": True, "checked": len(closed_prs), "results": results}


# ==========================================================
# HUMAN-READABLE CONFIG SUMMARY (reads the latest Git-backed
# .rsc export -- purely deterministic, no LLM involved)
# ==========================================================

def summarize_router_config(router_name):
    path = os.path.join(BACKUP_DIR, f"{router_name}.rsc")

    if not os.path.exists(path):
        return {
            "success": False,
            "message": f"No backup found for '{router_name}' yet. Run a config backup first."
        }

    with open(path, "r") as f:
        lines = f.readlines()

    identity = None
    model = None
    serial = None
    ros_version = None
    generated = None
    current_section = None
    section_counts = {}

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("# ") and "by RouterOS" in stripped:
            parts = stripped[2:].split(" by RouterOS ")
            if len(parts) == 2:
                generated = parts[0].strip()
                ros_version = parts[1].strip()
        elif stripped.startswith("# model ="):
            model = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("# serial number ="):
            serial = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("/"):
            current_section = stripped
        elif current_section and (stripped.startswith("add ") or stripped.startswith("set ")):
            section_counts[current_section] = section_counts.get(current_section, 0) + 1

    top_sections = sorted(section_counts.items(), key=lambda x: -x[1])[:12]

    summary_lines = [
        f"Config summary for {router_name}",
        f"RouterOS {ros_version or 'unknown'} | Model: {model or 'unknown'} | Serial: {serial or 'unknown'}",
        f"Backup generated: {generated or 'unknown'} | {len(lines)} lines total",
        "",
        "Configuration breakdown (top sections):",
    ]
    for section, count in top_sections:
        summary_lines.append(f"  {section}: {count} entries")

    return {
        "success": True,
        "router": router_name,
        "summary": "\n".join(summary_lines),
        "total_lines": len(lines),
        "section_counts": section_counts,
    }


# ==========================================================
# FULL RAW CONFIG (entire .rsc export, no summarization)
# ==========================================================

def get_raw_router_config(router_name):
    path = os.path.join(BACKUP_DIR, f"{router_name}.rsc")

    if not os.path.exists(path):
        return {
            "success": False,
            "message": f"No backup found for '{router_name}' yet. Run a config backup first."
        }

    with open(path, "r") as f:
        content = f.read()

    return {
        "success": True,
        "router": router_name,
        "content": content,
        "total_lines": content.count("\n") + 1,
    }


# ==========================================================
# SPECIFIC CONFIG SECTION (e.g. "ip address config for kincar")
# ==========================================================

def _parse_config_sections(content):
    sections = {}
    current = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("/") and not stripped.startswith("//"):
            current = stripped
            sections.setdefault(current, [])
        elif current and stripped:
            sections[current].append(line)
    return sections


def get_config_section(router_name, query_text):
    path = os.path.join(BACKUP_DIR, f"{router_name}.rsc")

    if not os.path.exists(path):
        return {"success": False, "message": f"No backup found for '{router_name}' yet."}

    with open(path, "r") as f:
        content = f.read()

    sections = _parse_config_sections(content)
    query_lower = query_text.lower()

    best_header = None
    best_score = 0
    for header in sections:
        words = header.lstrip("/").split()
        score = sum(1 for w in words if w in query_lower)
        if score > best_score:
            best_score = score
            best_header = header

    if not best_header or best_score == 0:
        return {"success": False, "message": "No specific section matched."}

    lines = sections[best_header]
    body = "\n".join(lines)

    return {
        "success": True,
        "router": router_name,
        "section": best_header,
        "content": f"{best_header}\n{body}",
        "line_count": len(lines),
    }


# ==========================================================
# CONFIG DRIFT DETECTION (alerts only -- does NOT auto-commit)
# ==========================================================

import difflib
from app.services.incident_utils import raise_incident, resolve_incidents


def _get_committed_config(router_name):
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{router_name}.rsc"],
            cwd=BACKUP_DIR, check=True, capture_output=True, text=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def detect_config_drift():
    results = []

    for router_name in ROUTERS:

        committed = _get_committed_config(router_name)
        if committed is None:
            results.append({"router": router_name, "status": "no_baseline"})
            continue

        try:
            client = _ssh_client(router_name)
            stdin, stdout, stderr = client.exec_command("/export", timeout=30)
            live = stdout.read().decode("utf-8", errors="replace")
            client.close()
        except Exception as e:
            results.append({"router": router_name, "status": "error", "message": str(e)})
            continue

        if live.strip() == committed.strip():
            resolve_incidents(router_name, "CONFIG_DRIFT")
            results.append({"router": router_name, "status": "clean"})
            continue

        diff_lines = list(difflib.unified_diff(
            committed.splitlines(), live.splitlines(), lineterm="", n=0
        ))
        changed_count = sum(1 for l in diff_lines if l.startswith("+") or l.startswith("-"))
        diff_sample = "\n".join(diff_lines[:30])

        raise_incident(
            router=router_name,
            category="CONFIG_DRIFT",
            severity="WARNING",
            title=f"Configuration drift detected on {router_name}",
            description=(
                f"Live config differs from the last Git-committed backup "
                f"({changed_count} changed lines). This may be an unauthorized "
                f"or unrecorded manual change. Sample diff:\\n{diff_sample}"
            ),
            source="Drift Detection"
        )
        results.append({"router": router_name, "status": "drift", "changed_lines": changed_count})

    return {"success": True, "results": results}


# ==========================================================
# ROUTER-SIDE BACKUP FILE LISTING / DOWNLOAD (SFTP)
# ==========================================================

def list_backup_files_on_router(router_name):
    if router_name not in ROUTERS:
        return {"success": False, "message": f"Router '{router_name}' not found."}

    try:
        from app.routers.mikrotik import get_path
        files = get_path(router_name, "file")
    except Exception as e:
        return {"success": False, "message": f"Could not list files: {str(e)}"}

    backups = []
    for f in files:
        name = f.get("name", "")
        if name.endswith(".backup") or name.endswith(".rsc"):
            size_raw = f.get("size", 0)
            size_bytes = int(size_raw) if str(size_raw).isdigit() else 0
            backups.append({
                "name": name,
                "type": f.get("type"),
                "size_bytes": size_bytes,
                "last_modified": f.get("last-modified"),
            })

    backups.sort(key=lambda b: b["last_modified"] or "", reverse=True)

    return {"success": True, "router": router_name, "files": backups}


def download_backup_file_from_router(router_name, filename):
    """
    Downloads a specific file (by exact name, as returned by
    list_backup_files_on_router) from the router's local storage
    via SFTP over the existing SSH connection. RouterOS's own SSH
    server supports the SFTP subsystem, so no separate FTP
    credentials or connection are needed.
    """
    if router_name not in ROUTERS:
        raise Exception(f"Router '{router_name}' not found.")

    # Guard against path traversal -- only allow bare filenames
    # matching what RouterOS actually reports, not arbitrary paths.
    safe_name = os.path.basename(filename)
    if safe_name != filename or not (safe_name.endswith(".backup") or safe_name.endswith(".rsc")):
        raise Exception("Invalid filename.")

    client = _ssh_client(router_name)
    try:
        # RouterOS's SFTP subsystem tends to drop the channel on a single
        # large read() for multi-MB files. Reading in smaller chunks with
        # an explicit timeout and a transport keepalive avoids that.
        transport = client.get_transport()
        transport.set_keepalive(15)

        sftp = client.open_sftp()
        sftp.get_channel().settimeout(60)
        try:
            chunks = []
            with sftp.open(safe_name, "rb") as remote_file:
                remote_file.set_pipelined(False)
                while True:
                    chunk = remote_file.read(32768)
                    if not chunk:
                        break
                    chunks.append(chunk)
            data = b"".join(chunks)
        finally:
            sftp.close()
    finally:
        client.close()

    return data
