# Trello MCP Server — mock Trello card data exposed over MCP (port 8083).
#
# Every inbound request is validated against an Okta-issued access token before
# any tool is called. The token must be signed by OKTA_MCP_AS_ISSUER, carry the
# audience matching GATEWAY_MCP_URL, and include the scope "read:trello".
#
# This server is the final downstream resource in the A2A use case (T5):
#   Agent 2 exchanges T3 → T4 ID-JAG → T5 Trello access token (this server's audience)
#   and then calls get_trello_cards here with that access token as a Bearer header.

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
REQUIRED_SCOPE = "read:trello"

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
            unverified = jwt.decode(token, options={"verify_signature": False})
            print(f"[MCP] Token validation FAILED: {e}")
            print(f"[MCP] Token aud={unverified.get('aud')} | expected={os.getenv('GATEWAY_MCP_URL')}")
            return JSONResponse({"error": f"Invalid token: {str(e)}"}, status_code=401)

        return await call_next(request)


mcp = FastMCP(
    "Trello MCP Server",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
def get_trello_cards() -> dict:
    """
    Retrieve Trello cards assigned to the team.
    Returns a list of cards with task, description, and owner.
    """
    return {
        "cards": [
            {
                "id": "CARD-001",
                "task": "Fix login page redirect bug",
                "description": "Users are being redirected to a 404 after OAuth login. Investigate the callback URL mismatch and update the redirect URI in the app config.",
                "owner": "Team Member",
                "status": "In Progress",
            },
            {
                "id": "CARD-002",
                "task": "Update API rate limiting docs",
                "description": "The developer docs for the REST API are missing rate limit headers. Add examples for 429 responses and retry-after guidance.",
                "owner": "Team Member",
                "status": "To Do",
            },
        ]
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
    uvicorn.run(app, host="0.0.0.0", port=8083)
