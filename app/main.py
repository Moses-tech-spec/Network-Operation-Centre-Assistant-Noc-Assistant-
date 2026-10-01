from contextlib import asynccontextmanager

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from fastapi.openapi.utils import get_openapi
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.docs import get_redoc_html

from fastapi import FastAPI, HTTPException

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import ROUTERS

from app.database.database import initialize_database, db

from app.ai.assistant import MayaAssistant

from app.api.schemas import MayaQuestion

from app.scheduler.scheduler import (
    start_scheduler,
    stop_scheduler,
)

from app.services.search import UniversalSearch

from app.analyzer import analyze_customer

from app.services.incidents import IncidentEngine
from app.services.config_backup import (
    export_router_config,
    list_backup_files_on_router,
    download_backup_file_from_router,
    get_raw_router_config,
    summarize_router_config,
)
from app.services.posture import (
    _check_exposed_services,
    _check_default_admin,
    _check_full_group_users,
    _check_firewall_input_chain,
    _check_routeros_version,
)

from app.routers.mikrotik import (
    get_system_resource,
    get_interfaces,
    get_traffic,
    get_pppoe,
    get_queues,
    get_leases,
    get_logs,
    search_customer,
    disconnect_pppoe,
    block_customer,
    unblock_customer,
    set_queue_state_by_ip,
    check_website_access,
    reconnect_customer,
    reset_ppp_session,
    restart_interface,
    backup_router,
    backup_all_routers,
    reboot_router,
)


# ==========================================================
# Application Lifespan
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    print("=======================================")
    print("Starting Hyperwave Network API")
    print("=======================================")

    print("Initializing database...")
    initialize_database()

    print("Starting scheduler...")
    start_scheduler()

    yield

    print("Stopping scheduler...")
    stop_scheduler()

    print("Hyperwave Network API stopped.")


# ==========================================================
# FastAPI
# ==========================================================

import os

security = HTTPBasic(auto_error=False)

MAYA_API_USERNAME = os.environ.get("MAYA_API_USERNAME")
MAYA_API_PASSWORD = os.environ.get("MAYA_API_PASSWORD")


MAYA_BEARER_TOKEN = os.environ.get("MAYA_BEARER_TOKEN")


import base64
from fastapi.middleware.cors import CORSMiddleware
from app.services.auth_service import (
    create_users_table,
    create_user,
    delete_user,
    list_users,
    authenticate,
    decode_token,
)
from pydantic import BaseModel as _BaseModel


class LoginRequest(_BaseModel):
    username: str
    password: str


class CreateUserRequest(_BaseModel):
    username: str
    password: str
    role: str = "viewer"


def require_role(*allowed_roles):
    def _dependency(request: Request):
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token.")
        token = auth_header[len("Bearer "):]

        # Maya's own shared bearer token counts as automatic admin --
        # keeps her existing automated actions working unchanged.
        if MAYA_BEARER_TOKEN and secrets.compare_digest(token, MAYA_BEARER_TOKEN):
            return {"sub": "maya", "role": "admin"}

        payload = decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token.")
        if allowed_roles and payload.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return payload
    return _dependency



def verify_docs(request: Request):

    if request.url.path in ("/login",):
        return True

    auth_header = request.headers.get("authorization", "")

    # Accept a valid Bearer token (used by Open WebUI)
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        if MAYA_BEARER_TOKEN and secrets.compare_digest(token, MAYA_BEARER_TOKEN):
            return True
        # Not the shared Maya token -- try it as a personal JWT (dashboard users)
        jwt_payload = decode_token(token)
        if jwt_payload:
            return True
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token."
        )

    if not MAYA_API_USERNAME or not MAYA_API_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Server credentials not configured."
        )

    if not auth_header.startswith("Basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        decoded = base64.b64decode(auth_header[len("Basic "):]).decode("utf-8")
        username, _, password = decoded.partition(":")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Basic auth header",
            headers={"WWW-Authenticate": "Basic"},
        )

    correct_username = secrets.compare_digest(username, MAYA_API_USERNAME)
    correct_password = secrets.compare_digest(password, MAYA_API_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )

    return True


app = FastAPI(
    title="Hyperwave Network API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    dependencies=[Depends(verify_docs)],
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

create_users_table()

limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

import time as _time
import json as _json
from app.database.database import db as _audit_db

def _extract_identity(request: Request) -> str:
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        if MAYA_BEARER_TOKEN and secrets.compare_digest(token, MAYA_BEARER_TOKEN):
            return "maya-ai"
        payload = decode_token(token)
        if payload and payload.get("sub"):
            return f"user:{payload['sub']}"
        return "bearer_token"
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[len("Basic "):]).decode("utf-8")
            username, _, _ = decoded.partition(":")
            return f"basic:{username}"
        except Exception:
            return "basic:unknown"
    return "unauthenticated"

@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    start = _time.time()

    body_snippet = None
    if request.url.path in ("/ip/disable", "/ip/enable"):
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_snippet = body_bytes.decode("utf-8")[:500]
            async def receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive
        except Exception:
            body_snippet = None

    response = await call_next(request)

    duration_ms = int((_time.time() - start) * 1000)
    identity = _extract_identity(request)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        source_ip = forwarded_for.split(",")[0].strip()
    else:
        source_ip = request.client.host if request.client else "unknown"

    try:
        _audit_db.execute(
            "INSERT INTO audit_log (method, path, status_code, duration_ms, source_ip, identity, request_body) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (request.method, request.url.path, response.status_code, duration_ms, source_ip, identity, body_snippet)
        )
    except Exception as _e:
        print(f"AUDIT LOG WRITE FAILED: {_e}")

    return response


# ==========================================================
# Helper
# ==========================================================

def validate_router(router: str):

    if router not in ROUTERS:

        raise HTTPException(

            status_code=404,

            detail=f"Router '{router}' not found."

        )


# ==========================================================
# Root
# ==========================================================

@app.get("/", tags=["General"])
def root():

    return {

        "service": "Hyperwave Network API",

        "version": app.version,

        "status": "online",

        "routers": list(ROUTERS.keys())

    }


@app.get("/health", tags=["General"])
def health():

    return {

        "status": "healthy",

        "scheduler": "running"

    }


# ==========================================================
# Routers
# ==========================================================

@app.get("/v1/models", tags=["General"])
def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "maya", "object": "model", "created": 0, "owned_by": "moses-mwangi 0797198314"}
        ]
    }


@app.get("/routers", tags=["Routers"])
def routers():

    return {

        "count": len(ROUTERS),

        "routers": list(ROUTERS.keys())

    }


# ==========================================================
# Router System
# ==========================================================

@app.get("/router/{router}/system", tags=["Router"])
def router_system(router: str):

    validate_router(router)

    try:

        return get_system_resource(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Interfaces
# ==========================================================

@app.get("/router/{router}/interfaces", tags=["Router"])
def router_interfaces(router: str):

    validate_router(router)

    try:

        return get_interfaces(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Traffic
# ==========================================================

@app.get("/router/{router}/traffic/{interface}", tags=["Router"])
def router_traffic(router: str, interface: str):

    validate_router(router)

    try:

        return get_traffic(router, interface)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# PPPoE
# ==========================================================

@app.get("/router/{router}/pppoe", tags=["PPPoE"])
def router_pppoe(router: str):

    validate_router(router)

    try:

        return get_pppoe(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Queues
# ==========================================================

@app.get("/router/{router}/queues", tags=["Queues"])
def router_queues(router: str):

    validate_router(router)

    try:

        return get_queues(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# DHCP
# ==========================================================

@app.get("/router/{router}/leases", tags=["DHCP"])
def router_leases(router: str):

    validate_router(router)

    try:

        return get_leases(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Logs
# ==========================================================

@app.get("/router/{router}/logs", tags=["Logs"])
def router_logs(router: str):

    validate_router(router)

    try:

        return get_logs(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Customer Analysis
# ==========================================================

@app.get("/customer/{router}/{query}", tags=["Customers"])
def customer(router: str, query: str):

    validate_router(router)

    try:

        customer = search_customer(router, query)

        if not customer.get("match_found"):

            return customer

        analysis = analyze_customer(customer)

        analysis["match_found"] = True

        analysis["details"] = {

            "pppoe": customer.get("pppoe"),

            "lease": customer.get("lease"),

            "queue": customer.get("queue"),

        }

        return analysis

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Disconnect Customer
# ==========================================================

@app.post("/customer/{router}/{query}/disconnect", tags=["Customers"])
@limiter.limit("10/minute")
def disconnect_customer(request: Request, router: str, query: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return disconnect_pppoe(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Block / Unblock Customer
# ==========================================================

@app.post("/customer/{router}/{query}/block", tags=["Customers"])
@limiter.limit("10/minute")
def block_customer_endpoint(request: Request, router: str, query: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return block_customer(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/customer/{router}/{query}/unblock", tags=["Customers"])
@limiter.limit("10/minute")
def unblock_customer_endpoint(request: Request, router: str, query: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return unblock_customer(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Enable / Disable Queue by IP
# ==========================================================

from pydantic import BaseModel as _BaseModel

class IPToggleBody(_BaseModel):
    address: str


@app.post("/ip/disable", tags=["IP Control"])
@limiter.limit("10/minute")
def disable_ip(request: Request, body: IPToggleBody, _=Depends(require_role("admin"))):

    try:

        return set_queue_state_by_ip(body.address, disabled=True)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/ip/enable", tags=["IP Control"])
@limiter.limit("10/minute")
def enable_ip(request: Request, body: IPToggleBody, _=Depends(require_role("admin"))):

    try:

        return set_queue_state_by_ip(body.address, disabled=False)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Reconnect / Reset / Restart / Backup
# ==========================================================

@app.post("/customer/{router}/{query}/reconnect", tags=["Customers"])
@limiter.limit("10/minute")
def reconnect_customer_endpoint(request: Request, router: str, query: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return reconnect_customer(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/customer/{router}/{query}/reset", tags=["Customers"])
@limiter.limit("10/minute")
def reset_ppp_session_endpoint(request: Request, router: str, query: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return reset_ppp_session(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/{router}/interface/{interface_name}/restart", tags=["Router"])
def restart_interface_endpoint(router: str, interface_name: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return restart_interface(router, interface_name)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/{router}/backup", tags=["Router"])
def backup_router_endpoint(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return backup_router(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/backup-all", tags=["Router"])
def backup_all_routers_endpoint(_=Depends(require_role("admin"))):

    try:

        return backup_all_routers()

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Website / Route Diagnostics
# ==========================================================

@app.get("/diagnose/website/{target}", tags=["AI"])
def diagnose_website(target: str):

    try:

        return check_website_access(target)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Universal Search
# ==========================================================

@app.get("/search/{query}", tags=["AI"])
def universal_search(query: str):

    try:

        return UniversalSearch.search(query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Incident Engine
# ==========================================================

@app.post("/router/{router}/scan", tags=["Incident Engine"])
def scan_router(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return IncidentEngine.check_router(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.get("/router/{router}/incidents", tags=["Incident Engine"])
def incidents(router: str):

    validate_router(router)

    try:

        return IncidentEngine.history(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.get("/router/{router}/posture", tags=["Security Monitoring"])
def posture(router: str):

    validate_router(router)

    try:

        result = {
            "router": router,
            "services": _check_exposed_services(router),
            "default_admin": _check_default_admin(router),
            "full_group_users": _check_full_group_users(router),
            "firewall_input": _check_firewall_input_chain(router),
            "routeros_version": _check_routeros_version(router),
        }

        return result

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


# ==========================================================
# Maya AI Assistant
# ==========================================================

@app.post("/maya", tags=["Maya AI"])
def maya(question: MayaQuestion):

    return MayaAssistant.ask(question.question)

from pydantic import BaseModel
from typing import List


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "maya"
    messages: List[ChatMessage]
    temperature: float = 0.2


@app.post("/v1/chat/completions")
def chat_completion(request: ChatRequest):

    # Get the user's latest message
    question = request.messages[-1].content

    # Forward prior turns so Maya can resolve references like
    # "her connection" or "that router" back to what was discussed.
    history = [
        {"role": m.role, "content": m.content}
        for m in request.messages[:-1]
    ]

    # Ask Maya
    result = MayaAssistant.ask(question, history=history)

    # Support both dict and string responses
    if isinstance(result, dict):
        answer = result.get("answer", str(result))
    else:
        answer = str(result)

    return {
        "id": "chatcmpl-maya",
        "object": "chat.completion",
        "created": 0,
        "model": "maya",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": answer
                },
                "finish_reason": "stop"
            }
        ]
    }


@app.get("/openapi.json", include_in_schema=False)
def openapi(credentials: HTTPBasicCredentials = Depends(verify_docs)):
    return get_openapi(
        title=app.title,
        version="3.0.0",
        routes=app.routes,
    )


@app.get("/docs", include_in_schema=False)
def swagger(credentials: HTTPBasicCredentials = Depends(verify_docs)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Hyperwave Network API Docs",
    )


@app.get("/redoc", include_in_schema=False)
def redoc(credentials: HTTPBasicCredentials = Depends(verify_docs)):
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Hyperwave Network API ReDoc",
    )


# ==========================================================
# Authentication (per-user, JWT-based, separate from Maya's
# shared bearer token used above)
# ==========================================================

@app.post("/login", tags=["Auth"])
def login(payload: LoginRequest):
    result = authenticate(payload.username, payload.password)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return result


@app.post("/users", tags=["Auth"])
def add_user(payload: CreateUserRequest, _=Depends(require_role("admin"))):
    result = create_user(payload.username, payload.password, payload.role)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result


@app.get("/users", tags=["Auth"])
def get_users(_=Depends(require_role("admin"))):
    return {"users": list_users()}


@app.delete("/users/{username}", tags=["Auth"])
def remove_user(username: str, _=Depends(require_role("admin"))):
    return delete_user(username)


# ==========================================================
# BGP / OSPF (read-only, from data the scheduler already collects)
# ==========================================================

@app.get("/router/{router}/bgp", tags=["Router"])
def get_bgp_peers(router: str):
    rows = db.fetchall(
        """
        SELECT * FROM bgp_peers
        WHERE router=? AND id IN (
            SELECT MAX(id) FROM bgp_peers WHERE router=? GROUP BY peer_name
        )
        ORDER BY peer_name
        """,
        (router, router)
    )
    return {"router": router, "peers": [dict(r) for r in rows]}


@app.get("/router/{router}/ospf", tags=["Router"])
def get_ospf_neighbors(router: str):
    rows = db.fetchall(
        """
        SELECT * FROM ospf_neighbors
        WHERE router=? AND id IN (
            SELECT MAX(id) FROM ospf_neighbors WHERE router=? GROUP BY neighbor_id
        )
        ORDER BY neighbor_id
        """,
        (router, router)
    )
    return {"router": router, "neighbors": [dict(r) for r in rows]}


# ==========================================================
# Usage History (for graphing)
# ==========================================================

from datetime import datetime, timedelta

def resolve_range(range_key: str):
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())

    ranges = {
        "5m": (now - timedelta(minutes=5), now),
        "15m": (now - timedelta(minutes=15), now),
        "30m": (now - timedelta(minutes=30), now),
        "1h": (now - timedelta(hours=1), now),
        "3h": (now - timedelta(hours=3), now),
        "6h": (now - timedelta(hours=6), now),
        "12h": (now - timedelta(hours=12), now),
        "24h": (now - timedelta(hours=24), now),
        "today": (today_start, now),
        "yesterday": (today_start - timedelta(days=1), today_start),
        "day_before_yesterday": (today_start - timedelta(days=2), today_start - timedelta(days=1)),
        "this_week_so_far": (week_start, now),
        "7d": (now - timedelta(days=7), now),
        "30d": (now - timedelta(days=30), now),
    }
    return ranges.get(range_key)

@app.get("/router/{router}/usage/links", tags=["Usage"])
def link_usage(router: str, hours: int = 24, range: str = None):

    validate_router(router)

    if range:
        bounds = resolve_range(range)
        if not bounds:
            raise HTTPException(status_code=400, detail=f"Unknown range '{range}'.")
        start, end = bounds
        rows = db.fetchall(
            """
            SELECT interface_name, rx_rate, tx_rate, rx_bytes, tx_bytes, collected_at
            FROM link_usage_history
            WHERE router=? AND collected_at >= ? AND collected_at < ?
            ORDER BY collected_at ASC
            """,
            (router, start.isoformat(), end.isoformat())
        )
        return {"router": router, "range": range, "samples": rows}

    rows = db.fetchall(
        f"""
        SELECT interface_name, rx_rate, tx_rate, rx_bytes, tx_bytes, collected_at
        FROM link_usage_history
        WHERE router=? AND collected_at >= datetime('now', '-{hours} hours')
        ORDER BY collected_at ASC
        """,
        (router,)
    )

    return {"router": router, "hours": hours, "samples": rows}


@app.get("/customer/{router}/{query}/usage", tags=["Usage"])
def customer_usage(router: str, query: str, hours: int = 24, range: str = None):

    validate_router(router)

    customer = search_customer(router, query)
    queue = customer.get("queue")
    queue_name = queue["name"] if queue else query

    if range:
        bounds = resolve_range(range)
        if not bounds:
            raise HTTPException(status_code=400, detail=f"Unknown range '{range}'.")
        start, end = bounds
        rows = db.fetchall(
            """
            SELECT upload_rate, download_rate, upload_bytes, download_bytes, collected_at
            FROM queue_usage_history
            WHERE router=? AND queue_name=? AND collected_at >= ? AND collected_at < ?
            ORDER BY collected_at ASC
            """,
            (router, queue_name, start.isoformat(), end.isoformat())
        )
        return {"router": router, "queue_name": queue_name, "range": range, "samples": rows}

    rows = db.fetchall(
        f"""
        SELECT upload_rate, download_rate, upload_bytes, download_bytes, collected_at
        FROM queue_usage_history
        WHERE router=? AND queue_name=? AND collected_at >= datetime('now', '-{hours} hours')
        ORDER BY collected_at ASC
        """,
        (router, queue_name)
    )

    return {"router": router, "queue_name": queue_name, "hours": hours, "samples": rows}


# ==========================================================
# Config / Backups
# ==========================================================

@app.get("/router/{router}/backups", tags=["Config"])
def router_backups(router: str):

    validate_router(router)

    result = list_backup_files_on_router(router)

    if not result.get("success"):

        raise HTTPException(status_code=500, detail=result.get("message"))

    return result


@app.get("/router/{router}/backups/{filename}/download", tags=["Config"])
def router_backup_download(router: str, filename: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        data = download_backup_file_from_router(router, filename)

    except Exception as e:

        raise HTTPException(status_code=500, detail=str(e))

    from fastapi import Response as _RawResponse

    return _RawResponse(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/router/{router}/config/raw", tags=["Config"])
def router_config_raw(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    result = get_raw_router_config(router)

    if not result.get("success"):

        raise HTTPException(status_code=404, detail=result.get("message"))

    return result


@app.get("/router/{router}/config/summary", tags=["Config"])
def router_config_summary(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    result = summarize_router_config(router)

    if not result.get("success"):

        raise HTTPException(status_code=404, detail=result.get("message"))

    return result


@app.post("/router/{router}/config/refresh", tags=["Config"])
def router_config_refresh(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return export_router_config(router)

    except Exception as e:

        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# Reboot
# ==========================================================

@app.post("/router/{router}/reboot", tags=["Router"])
def reboot_router_endpoint(router: str, _=Depends(require_role("admin"))):

    validate_router(router)

    try:

        return reboot_router(router)

    except Exception as e:

        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# Daily Report (manual trigger, for testing/on-demand send)
# ==========================================================

from app.services.daily_report import send_daily_report as _send_daily_report

@app.post("/reports/daily/send", tags=["Reports"])
def trigger_daily_report(_=Depends(require_role("admin"))):

    try:

        return _send_daily_report()

    except Exception as e:

        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# User Activity (last seen / online, derived from audit_log)
# ==========================================================

@app.get("/users/activity", tags=["Auth"])
def users_activity(_=Depends(require_role("admin"))):

    rows = db.fetchall(
        """
        SELECT a.identity, datetime(a.timestamp, '+3 hours') as last_seen, a.source_ip
        FROM audit_log a
        INNER JOIN (
            SELECT identity, MAX(timestamp) as max_ts
            FROM audit_log
            WHERE identity LIKE 'user:%'
            GROUP BY identity
        ) latest ON a.identity = latest.identity AND a.timestamp = latest.max_ts
        WHERE a.identity LIKE 'user:%'
        """
    )

    activity = {}
    for r in rows:
        username = r["identity"].split("user:", 1)[1]
        activity[username] = {"last_seen": r["last_seen"], "last_ip": r["source_ip"]}

    online_row = db.fetchall(
        """
        SELECT DISTINCT identity FROM audit_log
        WHERE identity LIKE 'user:%'
        AND timestamp >= datetime('now', '-5 minutes')
        """
    )
    online_usernames = {r["identity"].split("user:", 1)[1] for r in online_row}

    return {
        "activity": [
            {
                "username": username,
                "last_seen": data["last_seen"],
                "last_ip": data["last_ip"],
                "online": username in online_usernames
            }
            for username, data in activity.items()
        ]
    }


# ==========================================================
# Activity Log (human-readable actions derived from audit_log)
# ==========================================================

import re as _re

_ACTION_PATTERNS = [
    (_re.compile(r"^/customer/([^/]+)/([^/]+)/disconnect$"), lambda m: f"disconnected {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/customer/([^/]+)/([^/]+)/block$"), lambda m: f"blocked {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/customer/([^/]+)/([^/]+)/unblock$"), lambda m: f"unblocked {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/customer/([^/]+)/([^/]+)/reconnect$"), lambda m: f"attempted reconnect for {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/customer/([^/]+)/([^/]+)/reset$"), lambda m: f"reset session for {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/router/([^/]+)/reboot$"), lambda m: f"rebooted {m.group(1)}"),
    (_re.compile(r"^/router/([^/]+)/backup$"), lambda m: f"backed up {m.group(1)}"),
    (_re.compile(r"^/router/backup-all$"), lambda m: "backed up all routers"),
    (_re.compile(r"^/router/([^/]+)/interface/([^/]+)/restart$"), lambda m: f"restarted interface {m.group(2)} on {m.group(1)}"),
    (_re.compile(r"^/router/([^/]+)/config/refresh$"), lambda m: f"refreshed config for {m.group(1)}"),
    (_re.compile(r"^/router/([^/]+)/scan$"), lambda m: f"ran a scan on {m.group(1)}"),
    (_re.compile(r"^/users$"), lambda m: "created a new user"),
    (_re.compile(r"^/users/([^/]+)$"), lambda m: f"removed user {m.group(1)}"),
]


def _describe_action(method, path, body_snippet):
    for pattern, describer in _ACTION_PATTERNS:
        m = pattern.match(path)
        if m:
            desc = describer(m)
            if path in ("/ip/disable", "/ip/enable") and body_snippet:
                try:
                    import json as _json
                    parsed = _json.loads(body_snippet)
                    addr = parsed.get("address", "")
                    action = "disabled" if path == "/ip/disable" else "enabled"
                    return f"{action} queue for {addr}"
                except Exception:
                    pass
            return desc
    if path in ("/ip/disable", "/ip/enable") and body_snippet:
        try:
            import json as _json
            parsed = _json.loads(body_snippet)
            addr = parsed.get("address", "")
            action = "disabled" if path == "/ip/disable" else "enabled"
            return f"{action} queue for {addr}"
        except Exception:
            pass
    return None


@app.get("/audit/actions", tags=["Auth"])
def audit_actions(limit: int = 100, _=Depends(require_role("admin"))):

    rows = db.fetchall(
        """
        SELECT identity, method, path, status_code, request_body,
               datetime(timestamp, '+3 hours') as when_eat
        FROM audit_log
        WHERE method IN ('POST', 'DELETE')
        ORDER BY timestamp DESC
        LIMIT 500
        """
    )

    results = []
    for r in rows:
        description = _describe_action(r["method"], r["path"], r["request_body"])
        if not description:
            continue

        identity = r["identity"] or "unknown"
        if identity.startswith("user:"):
            identity = identity.split("user:", 1)[1]
        elif identity == "maya-ai":
            identity = "Maya (AI)"

        results.append({
            "who": identity,
            "action": description,
            "status": "success" if r["status_code"] < 400 else "failed",
            "when": r["when_eat"]
        })

        if len(results) >= limit:
            break

    return {"actions": results}
