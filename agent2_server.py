"""
Agent 2 — Trello Sub-Agent Server

Receives a task from Agent 1 (OpenShell) with a T3 delegation token,
validates the delegation chain, does T4+T5 to get its own Trello token,
runs a LangGraph agent with Trello tools, and returns the result.

Flow:
  Agent 1 → POST /invoke  (Authorization: Bearer {T3 token})
  Agent 2 → validates T3
  Agent 2 → T4: org AS token-exchange  T3 → ID-JAG
  Agent 2 → T5: Trello AS jwt-bearer   ID-JAG → Trello token
  Agent 2 → LangGraph agent with Trello tools
  Agent 2 → returns result to Agent 1

Discovery endpoints:
  GET /.well-known/agent.json               — agent card
  GET /.well-known/oauth-protected-resource — AS + scopes

Usage:
  cp .env.example .env
  # Fill in all values in .env
  python agent2_server.py
  # then: ngrok http 8084
"""
import os, time, uuid, json, sys
from dotenv import load_dotenv
load_dotenv()
import requests, jwt, uvicorn
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

# ── Config — all values read from .env, no hardcoded secrets ──────────────────

okta_domain    = os.getenv("OKTA_DOMAIN",     "")
sub_client_id  = os.getenv("SUB_CLIENT_ID",   "")
sub_kid        = os.getenv("SUB_KID",         "")
sub_key_path   = os.getenv("SUB_KEY_PATH",    "")
trello_mcp_url = os.getenv("TRELLO_MCP_URL",  "")
agent2_base    = os.getenv("AGENT2_BASE_URL", "")

# AS identifiers — read from environment
sub_agent_as          = os.getenv("SUB_AGENT_AS_ID",    "")
sub_agent_as_issuer   = f"https://{okta_domain}/oauth2/{sub_agent_as}"
sub_agent_audience    = f"https://{okta_domain}/openshell-sub-agent"
trello_as             = os.getenv("TRELLO_AS_ID",       "")
trello_as_audience    = f"https://{okta_domain}/oauth2/{trello_as}"
trello_token_endpoint = f"https://{okta_domain}/oauth2/{trello_as}/v1/token"
org_token_endpoint    = f"https://{okta_domain}/oauth2/v1/token"
trello_resource       = trello_mcp_url

# ── Load Agent 2's RSA private key — used for private_key_jwt auth to Okta ────

with open(sub_key_path, "rb") as f:
    sub_private_key = load_pem_private_key(f.read(), password=None)
print("Sub-agent private key loaded")

# JWKS client — validates T3 tokens Agent 1 sends us
_jwks_client = jwt.PyJWKClient(f"{sub_agent_as_issuer}/v1/keys")

# ── Helpers ────────────────────────────────────────────────────────────────────

# Builds a short-lived signed JWT for Agent 2 to authenticate itself to Okta
def build_assertion(client_id, private_key, kid, endpoint):
    now = int(time.time())
    return jwt.encode(
        {"iss": client_id, "sub": client_id,
         "aud": endpoint, "iat": now, "exp": now + 300,
         "jti": str(uuid.uuid4())},
        private_key, algorithm="RS256", headers={"kid": kid}
    )


def validate_t3(token: str) -> dict:
    """Validate T3 token issued by sub-agent AS to Agent 1."""
    signing_key = _jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=sub_agent_audience,
        issuer=sub_agent_as_issuer,
    )
    return claims


def do_t4_t5(t3_token: str) -> str:
    """
    T4: org AS token-exchange  — T3 access token → ID-JAG (Agent 2 identity)
    T5: Trello AS jwt-bearer   — ID-JAG → Trello access token
    """
    # T4 — Agent 2 re-exchanges at org AS with its own client identity
    print("[Agent 2] T4: org AS token-exchange...")
    t4 = requests.post(org_token_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token":         t3_token,
        "subject_token_type":    "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type":  "urn:ietf:params:oauth:token-type:id-jag",
        "audience":              trello_as_audience,
        "scope":                 "read:trello",
        "client_id":             sub_client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      build_assertion(sub_client_id, sub_private_key, sub_kid, org_token_endpoint),
    })
    print(f"[Agent 2] T4 status={t4.status_code}")
    if t4.status_code != 200:
        raise RuntimeError(f"T4 failed: {t4.text[:300]}")
    id_jag = t4.json()["access_token"]

    # T5 — Agent 2 presents ID-JAG to Trello AS
    print("[Agent 2] T5: Trello AS jwt-bearer...")
    t5 = requests.post(trello_token_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":             id_jag,
        "client_id":             sub_client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      build_assertion(sub_client_id, sub_private_key, sub_kid, trello_token_endpoint),
    })
    print(f"[Agent 2] T5 status={t5.status_code}")
    if t5.status_code != 200:
        raise RuntimeError(f"T5 failed: {t5.text[:300]}")
    trello_token = t5.json()["access_token"]

    print("")
    print("=== A2A TOKEN CHAIN ===")
    print(f"[T3] Delegation Token (Agent 1 → Agent 2): {t3_token}")
    print(f"[T4] ID-JAG           (Agent 2 identity):  {id_jag}")
    print(f"[T5] Trello Token     (final access):       {trello_token}")
    print("=======================")
    print("")

    return trello_token


def parse_sse_json(resp):
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    raise ValueError(f"No SSE data line: {resp.text[:200]}")


def make_trello_tools(trello_token: str):
    """
    Create Trello tools with the Trello access token baked in.
    Tools call the Trello MCP server using T5 token.
    New tools can be added here — Agent 1 never knows about them until tools/list.
    """

    class _KeepAuth(requests.Session):
        def rebuild_auth(self, p, r): pass

    def _mcp_session():
        s = _KeepAuth()
        s.headers.update({
            "Authorization":              f"Bearer {trello_token}",
            "ngrok-skip-browser-warning": "true",
        })
        h = {"Content-Type": "application/json",
             "Accept":        "application/json, text/event-stream"}
        init = s.post(trello_mcp_url, headers=h, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "trello-agent-2", "version": "1.0"}},
        }, timeout=15)
        session_id = init.headers.get("mcp-session-id")
        return s, h, session_id

    @tool
    def get_trello_cards() -> dict:
        """Retrieve Trello cards assigned to the team."""
        s, h, sid = _mcp_session()
        resp = s.post(trello_mcp_url, headers={**h, "mcp-session-id": sid}, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_trello_cards", "arguments": {}},
        })
        payload = parse_sse_json(resp)
        for block in payload.get("result", {}).get("content", []):
            if block.get("type") == "text":
                return json.loads(block["text"])
        return {"error": "No content in MCP response"}

    return [get_trello_cards]


# ── LLM — Anthropic Haiku, used by the LangGraph ReAct agent in /invoke ────────

llm = ChatAnthropic(
    model="claude-haiku-4-5-20251001",
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
    max_tokens=512,
)

SYSTEM_PROMPT = (
    "You are a Trello task management sub-agent. "
    "Use your tools to retrieve Trello data and answer the user's request concisely."
)

# ── FastAPI app — three endpoints: agent card, AS discovery, and /invoke ────────

app = FastAPI(title="Trello Sub-Agent (Agent 2)")


@app.get("/.well-known/agent.json")
async def agent_card():
    """Agent card — Agent 1 fetches this to discover who Agent 2 is."""
    return {
        "name":        "Trello Sub-Agent",
        "description": "Retrieves and summarizes Trello cards for the team.",
        "url":         agent2_base,
        "version":     "1.0",
        "capabilities": ["get_trello_cards"],
        "authorization": {
            "type":                 "okta_a2a",
            "authorization_server": sub_agent_as_issuer,
            "required_scope":       "openshell:invoke",
        },
    }


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """RFC 8707 — tells Agent 1 which AS to target for the delegation token."""
    return {
        "resource":                    agent2_base,
        "authorization_servers":       [sub_agent_as_issuer],
        "bearer_methods_supported":    ["header"],
        "scopes_supported":            ["openshell:invoke"],
    }


@app.post("/invoke")
async def invoke(request: Request):
    # ── Step 1: validate T3 token from Agent 1 ─────────────────────────────────
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "Missing Bearer token"}, status_code=401)
    t3_token = auth.split(" ", 1)[1]

    try:
        claims = validate_t3(t3_token)
    except Exception as e:
        print(f"[Agent 2] T3 validation FAILED: {e}")
        return JSONResponse({"error": f"Invalid delegation token: {e}"}, status_code=401)

    delegation_chain = claims.get("act", {})
    print(f"[Agent 2] T3 valid. sub={claims.get('sub')} act={delegation_chain}")

    # ── Step 2: parse task ──────────────────────────────────────────────────────
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    task = body.get("task", "").strip()
    if not task:
        return JSONResponse({"error": "No task provided"}, status_code=400)
    print(f"[Agent 2] Task received: {task!r}")

    # ── Step 3: T4+T5 — get Trello token with Agent 2's own identity ───────────
    try:
        trello_token = do_t4_t5(t3_token)
    except Exception as e:
        print(f"[Agent 2] Token exchange error: {e}")
        return JSONResponse({"error": f"Token exchange failed: {e}"}, status_code=500)

    # ── Step 4: run LangGraph agent with Trello tools ───────────────────────────
    tools = make_trello_tools(trello_token)
    agent = create_react_agent(llm, tools=tools, prompt=SYSTEM_PROMPT)

    try:
        result = agent.invoke({"messages": [{"role": "user", "content": task}]})
        answer = result["messages"][-1].content
        print(f"[Agent 2] Result: {answer[:100]}...")
        return {
            "result":           answer,
            "delegation_chain": delegation_chain,
            "agent":            "trello-sub-agent-v1",
        }
    except Exception as e:
        print(f"[Agent 2] LangGraph error: {e}")
        return JSONResponse({"error": f"Agent error: {e}"}, status_code=500)


if __name__ == "__main__":
    print(f"Starting Trello Sub-Agent on port 8084")
    print(f"  sub_client_id : {sub_client_id}")
    print(f"  sub_agent_as  : {sub_agent_as}")
    print(f"  trello_as     : {trello_as}")
    print(f"  agent2_base   : {agent2_base}")
    print(f"  trello_mcp    : {trello_mcp_url}")
    uvicorn.run(app, host="0.0.0.0", port=8084)
