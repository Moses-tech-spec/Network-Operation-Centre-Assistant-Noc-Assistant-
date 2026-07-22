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

from app.database.database import initialize_database

from app.ai.assistant import MayaAssistant

from app.api.schemas import MayaQuestion

from app.scheduler.scheduler import (
    start_scheduler,
    stop_scheduler,
)

from app.services.search import UniversalSearch

from app.analyzer import analyze_customer

from app.services.incidents import IncidentEngine

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


def verify_docs(request: Request):

    auth_header = request.headers.get("authorization", "")

    # Accept a valid Bearer token (used by Open WebUI)
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        if MAYA_BEARER_TOKEN and secrets.compare_digest(token, MAYA_BEARER_TOKEN):
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
def disconnect_customer(request: Request, router: str, query: str):

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
def block_customer_endpoint(request: Request, router: str, query: str):

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
def unblock_customer_endpoint(request: Request, router: str, query: str):

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
def disable_ip(request: Request, body: IPToggleBody):

    try:

        return set_queue_state_by_ip(body.address, disabled=True)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/ip/enable", tags=["IP Control"])
@limiter.limit("10/minute")
def enable_ip(request: Request, body: IPToggleBody):

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
def reconnect_customer_endpoint(request: Request, router: str, query: str):

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
def reset_ppp_session_endpoint(request: Request, router: str, query: str):

    validate_router(router)

    try:

        return reset_ppp_session(router, query)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/{router}/interface/{interface_name}/restart", tags=["Router"])
def restart_interface_endpoint(router: str, interface_name: str):

    validate_router(router)

    try:

        return restart_interface(router, interface_name)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/{router}/backup", tags=["Router"])
def backup_router_endpoint(router: str):

    validate_router(router)

    try:

        return backup_router(router)

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)

        )


@app.post("/router/backup-all", tags=["Router"])
def backup_all_routers_endpoint():

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
def scan_router(router: str):

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
