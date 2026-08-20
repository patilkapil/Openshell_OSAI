# Jira MCP Server — mock Jira and fraud analysis tools exposed over MCP (port 8082).
#
# Every inbound request is validated against an Okta-issued access token before
# any tool is called. The token must be signed by OKTA_MCP_AS_ISSUER, carry the
# audience matching GATEWAY_MCP_URL, and include the scope "mcp:read".
#
# This server is the downstream resource in the XAA use case:
#   Agent 1 exchanges the user's ID Token → ID-JAG → Access Token (this server's audience)
#   and then calls tools here with that access token as a Bearer header.

import os
import uvicorn
import jwt
import requests as http_requests
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

load_dotenv()

NGROK_BASE_URL = os.getenv("NGROK_BASE_URL")
OKTA_AS_ISSUER = os.getenv("OKTA_MCP_AS_ISSUER")
OKTA_JWKS_URL  = f"{OKTA_AS_ISSUER}/v1/keys"
REQUIRED_SCOPE = "mcp:read"

# JWKS client fetches Okta's public keys to verify incoming token signatures
_jwks_client = jwt.PyJWKClient(OKTA_JWKS_URL)


# Validates Bearer token on every request — checks signature, audience, issuer, and scope
class BearerTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        print(f"[MCP] {request.method} {request.url.path} | Auth: {request.headers.get('Authorization', 'NONE')[:60]}")
        # Skip auth for discovery endpoint
        if request.url.path == "/.well-known/oauth-protected-resource":
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "Missing Bearer token"}, status_code=401)

        token = auth.split(" ", 1)[1]
        try:
            signing_key = _jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=os.getenv("GATEWAY_MCP_URL"),
                issuer=OKTA_AS_ISSUER,
            )
            scopes = claims.get("scp", [])
            if REQUIRED_SCOPE not in scopes:
                return JSONResponse({"error": f"Missing required scope: {REQUIRED_SCOPE}"}, status_code=403)
        except Exception as e:
            print(f"[MCP] Token validation FAILED: {e}")
            return JSONResponse({"error": f"Invalid token: {str(e)}"}, status_code=401)

        return await call_next(request)


mcp = FastMCP(
    "AuditBot Fraud Analysis MCP Server",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
def get_transaction_records(case_id: str) -> dict:
    """
    Retrieve transaction records for a fraud investigation case.
    Returns a list of flagged transactions associated with the case ID.
    """
    return {
        "case_id": case_id,
        "transactions": [
            {"id": f"TXN-{case_id}-A", "description": "Wire Transfer — Flagged Merchant",      "amount": "$14,500", "status": "flagged"},
            {"id": f"TXN-{case_id}-B", "description": "ATM Withdrawal — Unusual Location",      "amount": "$2,000",  "status": "flagged"},
            {"id": f"TXN-{case_id}-C", "description": "Online Purchase — High-Risk Country",    "amount": "$890",    "status": "under_review"},
            {"id": f"TXN-{case_id}-D", "description": "Account Transfer — Structuring Pattern", "amount": "$9,900",  "status": "flagged"},
        ],
        "total_flagged": 4,
        "case_severity": "HIGH",
    }


@mcp.tool()
def get_risk_score(account_id: str) -> dict:
    """
    Run a risk assessment on a customer account.
    Returns risk indicators and an overall risk score.
    """
    return {
        "account_id": account_id,
        "risk_score": 87,
        "risk_level": "CRITICAL",
        "indicators": [
            {"signal": "Velocity Check",        "detail": "12 transactions in 2 hours",          "severity": "HIGH"},
            {"signal": "Geo-anomaly",            "detail": "Login from 3 countries in 24 hours",  "severity": "HIGH"},
            {"signal": "Device Fingerprint",     "detail": "New unrecognized device",             "severity": "MEDIUM"},
            {"signal": "Blacklist Match",        "detail": "Associated with known fraud ring",    "severity": "CRITICAL"},
        ],
        "recommendation": "Immediate account freeze recommended pending analyst review.",
    }


@mcp.tool()
def get_account_status(account_id: str) -> dict:
    """
    Retrieve the current status and profile of a customer account.
    """
    return {
        "account_id": account_id,
        "holder":      "Jane Doe",
        "status":      "ACTIVE",
        "opened":      "2019-03-15",
        "balance":     "$42,310.00",
        "flags": [
            "Large cash deposit — 2026-06-28",
            "Multiple failed login attempts — 2026-06-29",
        ],
        "freeze_eligible": True,
    }


@mcp.tool()
def get_jira_details(task_id: str) -> dict:
    """
    Retrieve Jira ticket details for a given task ID.
    Returns ticket metadata, description, and current status.
    """
    tickets = {
        "TASK-001": {
            "task_id": "TASK-001",
            "issue_type": "Security Investigation",
            "summary": "Investigate suspicious activity on service account svc-deploy-9821",
            "description": (
                "SIEM alert triggered on svc-deploy-9821. Review syslogs for anomalous access patterns "
                "and cross-reference with recent deployment activity. Check for privilege escalation, "
                "unexpected API calls, or lateral movement indicators. Determine if account should be "
                "suspended pending root cause analysis."
            ),
            "status": "In Progress",
            "priority": "High",
            "sprint": "Security Sprint 14",
            "story_points": 3,
            "assignee": "analyst@example.com",
            "assignee_role": "Security Analyst",
            "reporter": "siem-alerts@example.internal",
            "team": "Application Security",
            "created": "2026-08-10T09:15:00Z",
            "updated": "2026-08-12T14:32:00Z",
            "due_date": "2026-08-15",
            "labels": ["siem", "service-account", "privilege-escalation"],
            "components": ["Identity & Access", "Infrastructure Security"],
            "linked_account": "svc-deploy-9821",
            "linked_case": "CASE-4471",
        }
    }
    if task_id in tickets:
        return tickets[task_id]
    return {"error": f"Ticket {task_id} not found", "task_id": task_id}


@mcp.tool()
def check_sanctions(name: str) -> dict:
    """
    Check whether a person or entity appears on a sanctions or watchlist.
    """
    watchlist_hits = [
        {"list": "OFAC SDN",     "match": "Jane D.",     "confidence": "72%"},
        {"list": "FinCEN Alert", "match": "J. Doe",      "confidence": "65%"},
    ]
    return {
        "query":      name,
        "hits":       watchlist_hits,
        "hit_count":  len(watchlist_hits),
        "status":     "REVIEW_REQUIRED",
        "note":       "Potential matches found. Manual verification required before action.",
    }


# RFC 8707 discovery endpoint — tells callers which AS to get a token from
async def oauth_protected_resource(request):
    return JSONResponse({
        "resource": NGROK_BASE_URL,
        "authorization_servers": [OKTA_AS_ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read"],
    })


mcp_starlette = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app):
    async with mcp_starlette.router.lifespan_context(mcp_starlette):
        yield


# Starlette app: discovery route first (no auth), all other routes go through MCP + middleware
app = Starlette(
    lifespan=lifespan,
    routes=[
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource),
        Mount("/", app=mcp_starlette),
    ],
)
app.add_middleware(BearerTokenMiddleware)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8082)
