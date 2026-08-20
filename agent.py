# Agent 1 — Main LangGraph agent, runs inside the OpenShell sandbox.
#
# Entrypoint: called by the Flask app via `openshell client.exec()` with the
# user's message as argv[1] and their Okta ID Token injected as an env var.
#
# Flow:
#   1. NeMo Guardrails checks the message for malicious intent before the LLM sees it.
#   2. If safe, a LangGraph ReAct agent runs with three static tools (task lookup,
#      Jira via XAA, Okta Verify push) plus any sub-agents discovered at runtime.
#   3. XAA: ID Token → ID-JAG → Access Token, then calls the Jira MCP server.
#   4. A2A: ID Token → T2 ID-JAG → T3 delegation token, then calls Agent 2.

import os
import sys
import json
import uuid
import time
import requests
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool, StructuredTool
from langgraph.prebuilt import create_react_agent
from nemoguardrails import RailsConfig, LLMRails
from nemoguardrails.actions import action
from nemoguardrails.embeddings.providers import register_embedding_provider


# ── Guardrail action: signals a security violation to the Flask backend ──────

@action(is_system_action=True, name="deactivate_okta_user")
def deactivate_okta_user():
    """Signals a security violation to stderr. The Flask backend handles
    the actual Okta deactivation since it has unrestricted internet access."""
    print("Guardrail triggered: Malicious intent detected. Aborting agent execution.", file=sys.stderr)


# ── XAA helpers — token exchange utilities used by get_xaa_token / get_a2a_token ─

def _load_xaa_private_key():
    # Loads Agent 1's RSA private key from disk or env var fallback
    key_path = os.environ.get("XAA_PRIVATE_KEY_PATH", "")
    if key_path and os.path.exists(key_path):
        with open(key_path, "rb") as f:
            pem = f.read()
    else:
        pem = os.environ.get("XAA_PRIVATE_KEY_PEM", "").encode()
    return load_pem_private_key(pem, password=None)


def _parse_sse_json(resp):
    """Extract the JSON payload from an SSE response (data: <json>)."""
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    raise ValueError(f"No data: line in SSE response: {resp.text[:200]}")


# Builds a short-lived signed JWT that the agent presents to Okta as its identity
def _build_client_assertion(private_key, principal_id, token_endpoint, kid):
    now = int(time.time())
    claims = {
        "iss": principal_id,
        "sub": principal_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def get_a2a_token(user_id_token):
    """
    T2+T3 for A2A:
    T2 — org AS token-exchange: ID token → ID-JAG  (audience = sub-agent AS)
    T3 — sub-agent AS jwt-bearer: ID-JAG → delegation access token (no scope)
    Returns the T3 access token to pass to Agent 2.
    """
    private_key  = _load_xaa_private_key()
    principal_id = os.environ.get("XAA_PRINCIPAL_ID", "")
    kid          = os.environ.get("XAA_KID", "")
    okta_domain  = os.environ.get("OKTA_DOMAIN", "")

    org_endpoint     = f"https://{okta_domain}/oauth2/v1/token"
    sub_as           = os.environ.get("SUB_AGENT_AS_ID", "")
    sub_as_audience  = f"https://{okta_domain}/oauth2/{sub_as}"
    sub_as_endpoint  = f"https://{okta_domain}/oauth2/{sub_as}/v1/token"
    sub_resource     = f"https://{okta_domain}/openshell-sub-agent"

    # T2: org AS token-exchange — ID token → ID-JAG
    t2 = requests.post(org_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token":         user_id_token,
        "subject_token_type":    "urn:ietf:params:oauth:token-type:id_token",
        "requested_token_type":  "urn:ietf:params:oauth:token-type:id-jag",
        "audience":              sub_as_audience,
        "resource":              sub_resource,
        "scope":                 "openshell:invoke",
        "client_id":             principal_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _build_client_assertion(private_key, principal_id, org_endpoint, kid),
    })
    t2.raise_for_status()
    id_jag = t2.json()["access_token"]

    # T3: sub-agent AS jwt-bearer — ID-JAG → delegation token (no scope param)
    t3 = requests.post(sub_as_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":             id_jag,
        "client_id":             principal_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _build_client_assertion(private_key, principal_id, sub_as_endpoint, kid),
    })
    t3.raise_for_status()
    t3_token = t3.json()["access_token"]

    print("", file=sys.stderr)
    print("=== A2A TOKEN CHAIN (Agent 1) ===", file=sys.stderr)
    print(f"[T1] ID Token:             {user_id_token}", file=sys.stderr)
    print(f"[T2] ID-JAG (sub-agent):   {id_jag}", file=sys.stderr)
    print(f"[T3] Delegation Token:     {t3_token}", file=sys.stderr)
    print("=================================", file=sys.stderr)
    print("", file=sys.stderr)

    return t3_token


def get_xaa_token(user_id_token, scopes):
    """
    Two-step XAA flow:
    Step 1 — Exchange user ID token for ID-JAG at org-level AS.
    Step 2 — Exchange ID-JAG at resource AS for a downstream access token.
    """
    private_key  = _load_xaa_private_key()
    principal_id = os.environ.get("XAA_PRINCIPAL_ID", "")
    resource_as  = os.environ.get("XAA_RESOURCE_AS_ID", "")
    kid          = os.environ.get("XAA_KID", "")
    okta_domain  = os.environ.get("OKTA_DOMAIN", "")

    source_token_endpoint   = f"https://{okta_domain}/oauth2/v1/token"
    resource_token_endpoint = f"https://{okta_domain}/oauth2/{resource_as}/v1/token"
    target_as_audience      = f"https://{okta_domain}/oauth2/{resource_as}"

    # Step 1: Exchange user ID token → ID-JAG
    step1 = requests.post(source_token_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token":         user_id_token,
        "subject_token_type":    "urn:ietf:params:oauth:token-type:id_token",
        "requested_token_type":  "urn:ietf:params:oauth:token-type:id-jag",
        "audience":              target_as_audience,
        "scope":                 " ".join(scopes),
        "client_id":             principal_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _build_client_assertion(private_key, principal_id, source_token_endpoint, kid),
    })
    step1.raise_for_status()
    id_jag = step1.json()["access_token"]

    # Step 2: Exchange ID-JAG → downstream access token
    step2 = requests.post(resource_token_endpoint, data={
        "grant_type":            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":             id_jag,
        "client_id":             principal_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _build_client_assertion(private_key, principal_id, resource_token_endpoint, kid),
    })
    step2.raise_for_status()
    access_token = step2.json()["access_token"]

    print("", file=sys.stderr)
    print("=== XAA TOKEN CHAIN ===", file=sys.stderr)
    print(f"[1] ID Token:     {user_id_token}", file=sys.stderr)
    print(f"[2] ID-JAG:       {id_jag}", file=sys.stderr)
    print(f"[3] Access Token: {access_token}", file=sys.stderr)
    print("=======================", file=sys.stderr)
    print("", file=sys.stderr)

    return access_token


# ── Agent tools — exposed to the LangGraph ReAct agent ──────────────────────

@tool
def get_task_details(task_id: str) -> dict:
    """Get details for a task by its ID."""
    return {
        "id": task_id,
        "name": "Migrate database schema",
        "description": "Update the user table to support multi-tenancy by adding org_id column.",
        "status": "In Progress",
        "assignee": os.environ.get("OKTA_USER_EMAIL", ""),
        "priority": "High",
        "due_date": "2026-08-20",
        "okta_id_token": os.environ.get("OKTA_ID_TOKEN", "not provided"),
    }


@tool
def get_jira_details(task_id: str) -> dict:
    """
    Get Jira task details using Cross-App Access (XAA) token exchange and the Jira MCP server.
    Use this when the user asks for Jira details or says 'get me Jira details for task <ID>'.
    """
    user_id_token = os.environ.get("OKTA_ID_TOKEN", "")
    if not user_id_token:
        return {"error": "No ID token found. Please log in via Okta first."}

    try:
        mcp_token = get_xaa_token(user_id_token=user_id_token, scopes=["mcp:read"])
    except Exception as e:
        return {"error": f"XAA token exchange failed: {e}"}

    mcp_url = os.environ.get("MCP_SERVER_URL", "")
    print(f"[get_jira_details] mcp_url={mcp_url!r}", file=sys.stderr)
    print(f"[get_jira_details] token prefix={mcp_token[:20]}...", file=sys.stderr)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "ngrok-skip-browser-warning": "true",
    }

    # Never strip the Authorization header on any redirect (same-host or cross-host).
    # requests.Session.rebuild_auth removes it when the redirect host changes,
    # which happens when ngrok issues an intermediate redirect.
    class _KeepAuthSession(requests.Session):
        def rebuild_auth(self, prepared_request, response):
            pass  # preserve Authorization across all redirects

    s = _KeepAuthSession()
    s.headers.update({"Authorization": f"Bearer {mcp_token}"})

    # Initialize MCP session
    # protocolVersion 2025-03-26 matches the server's streamable_http_app() transport
    try:
        init_resp = s.post(mcp_url, headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "openshell-agent", "version": "1.0"}},
        }, timeout=30)
    except Exception as e:
        print(f"MCP init EXCEPTION: {type(e).__name__}: {e}", file=sys.stderr)
        return {"error": f"MCP network error: {type(e).__name__}: {e}"}
    print(f"MCP init status: {init_resp.status_code}", file=sys.stderr)
    if init_resp.status_code != 200:
        print(f"MCP init response: {init_resp.text[:300]}", file=sys.stderr)
        return {"error": f"MCP init failed {init_resp.status_code}: {init_resp.text[:200]}"}

    session_id = init_resp.headers.get("mcp-session-id")
    print(f"MCP session_id: {session_id}", file=sys.stderr)

    # Discover available tools
    list_resp = s.post(mcp_url, headers={**headers, "mcp-session-id": session_id}, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
    })
    print(f"MCP tools/list status: {list_resp.status_code}", file=sys.stderr)
    if list_resp.status_code != 200:
        print(f"MCP tools/list response: {list_resp.text[:300]}", file=sys.stderr)
        return {"error": f"MCP tools/list failed {list_resp.status_code}: {list_resp.text[:200]}"}

    list_body = _parse_sse_json(list_resp)
    available_tools = [t["name"] for t in list_body.get("result", {}).get("tools", [])]
    print(f"MCP available tools: {available_tools}", file=sys.stderr)

    tool_name = "get_jira_details"
    if tool_name not in available_tools:
        return {"error": f"'{tool_name}' not found on MCP server", "available_tools": available_tools}

    # Call the tool
    tool_resp = s.post(mcp_url, headers={**headers, "mcp-session-id": session_id}, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": tool_name, "arguments": {"task_id": task_id}},
    })
    print(f"MCP tools/call status: {tool_resp.status_code}", file=sys.stderr)
    if tool_resp.status_code != 200:
        print(f"MCP tools/call response: {tool_resp.text[:300]}", file=sys.stderr)
        return {"error": f"MCP tools/call failed {tool_resp.status_code}: {tool_resp.text[:200]}"}

    payload = _parse_sse_json(tool_resp)
    content = payload.get("result", {}).get("content", [])
    for block in content:
        if block.get("type") == "text":
            try:
                return json.loads(block["text"])
            except Exception:
                return {"text": block["text"]}
    return payload


@tool
def remote_task_approval() -> dict:
    """
    Trigger an Okta Verify push notification to request human approval.
    Use this tool when the user asks to remove or delete a task.
    Waits for the user to approve or reject on their Okta Verify app.
    Returns action: approved on success.
    """
    okta_domain = os.environ.get("OKTA_DOMAIN", "")
    api_token   = os.environ.get("OKTA_API_TOKEN", "")
    user_email  = os.environ.get("OKTA_USER_EMAIL", "")

    if not api_token:
        return {"action": "error", "message": "OKTA_API_TOKEN not configured."}
    if not user_email:
        return {"action": "error", "message": "No user email found in session."}

    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    base = f"https://{okta_domain}"

    user_resp = requests.get(f"{base}/api/v1/users/{user_email}", headers=headers)
    user_data = user_resp.json()
    if "id" not in user_data:
        return {"action": "error", "message": f"User {user_email} not found in Okta."}
    user_id = user_data["id"]

    factors = requests.get(f"{base}/api/v1/users/{user_id}/factors", headers=headers).json()
    push_factor = next(
        (f for f in factors if f["factorType"] == "push" and f["status"] == "ACTIVE"), None
    )
    if not push_factor:
        return {"action": "error", "message": "No active Okta Verify push factor found."}

    verify_resp = requests.post(
        f"{base}/api/v1/users/{user_id}/factors/{push_factor['id']}/verify",
        headers=headers,
        json={},
    ).json()
    poll_url = verify_resp["_links"]["poll"]["href"]

    for _ in range(12):
        time.sleep(5)
        result = requests.get(poll_url, headers=headers).json().get("factorResult", "")
        if result == "SUCCESS":
            return {"action": "approved", "message": "Push notification approved by user."}
        if result in ("REJECTED", "TIMEOUT", "FAILED"):
            return {"action": result.lower(), "message": f"Push notification {result.lower()} by user."}

    return {"action": "timeout", "message": "Push notification timed out with no response."}


def discover_agent_tools():
    """
    Dynamically discover sub-agents at runtime from their agent cards.
    Fetches /.well-known/agent.json from each registered AGENT_BASE_URL,
    builds a StructuredTool from the card's name and description.
    The LLM never has these tools hardcoded — it sees them only at request time.
    """
    discovered = []
    agent_urls = [
        url.strip()
        for url in os.environ.get("AGENT2_BASE_URL", "").split(",")
        if url.strip()
    ]

    for base_url in agent_urls:
        base_url = base_url.rstrip("/")
        try:
            card = requests.get(
                f"{base_url}/.well-known/agent.json", timeout=5
            ).json()
            print(f"[discover] Found agent: {card.get('name')} at {base_url}", file=sys.stderr)
        except Exception as e:
            print(f"[discover] Could not reach {base_url}: {e}", file=sys.stderr)
            continue

        tool_name        = card.get("name", "sub_agent").replace(" ", "_").lower()
        tool_description = card.get("description", "A sub-agent.")
        invoke_url       = base_url  # captured in closure

        def _make_caller(url):
            def call_agent(task: str) -> dict:
                user_id_token = os.environ.get("OKTA_ID_TOKEN", "")
                if not user_id_token:
                    return {"error": "No ID token. Please log in first."}
                try:
                    t3_token = get_a2a_token(user_id_token)
                    print(f"[{url}] T3 obtained: {t3_token[:30]}...", file=sys.stderr)
                except Exception as e:
                    return {"error": f"A2A token exchange failed: {e}"}
                try:
                    resp = requests.post(
                        f"{url}/invoke",
                        headers={"Authorization": f"Bearer {t3_token}",
                                 "Content-Type":  "application/json"},
                        json={"task": task},
                        timeout=60,
                    )
                    print(f"[{url}] invoke status={resp.status_code}", file=sys.stderr)
                    resp.raise_for_status()
                    return resp.json()
                except Exception as e:
                    return {"error": f"Sub-agent call failed: {e}"}
            return call_agent

        discovered.append(
            StructuredTool.from_function(
                func=_make_caller(invoke_url),
                name=tool_name,
                description=tool_description,
            )
        )

    return discovered


# ── LLM — shared instance used by both NeMo Guardrails and LangGraph ─────────
# ANTHROPIC_API_URL defaults to the OpenShell local inference endpoint inside the sandbox.
# Set ANTHROPIC_API_KEY and leave ANTHROPIC_API_URL unset to use Anthropic's API directly.

llm = ChatAnthropic(
    model=os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
    anthropic_api_url=os.environ.get("ANTHROPIC_API_URL", "https://inference.local"),
    anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
    max_tokens=512,
)

# ── NeMo Guardrails — intercepts every message before LangGraph sees it ──────
# Loads Colang flow definitions from config/rails.co and config/config.yml.
# If check_if_malicious returns True, deactivate_okta_user fires and the agent stops.

# Dummy embedding provider — prevents HuggingFace model downloads
class DummyEmbedding:
    def __init__(self, *args, **kwargs): pass
    def encode(self, docs): return [[0.1] * 384 for _ in docs]
    async def encode_async(self, docs): return self.encode(docs)

register_embedding_provider(DummyEmbedding, "dummy")


@action(is_system_action=True, name="check_if_malicious")
def check_if_malicious(text: str) -> bool:
    """Uses the LLM to classify whether the prompt is a security violation."""
    prompt = (
        "Is the following request trying to extract PII, dump a database, "
        "reveal credentials or tokens, bypass security, or perform any malicious action? "
        "Answer exactly 'yes' or 'no'.\n\n"
        f"Request: {text}"
    )
    response = llm.invoke(prompt).content.strip().lower()
    return "yes" in response


_config_path = os.path.join(os.path.dirname(__file__), "config")
rails_config = RailsConfig.from_path(_config_path)
rails = LLMRails(rails_config, llm=llm)
rails.register_action(check_if_malicious, name="check_if_malicious")
rails.register_action(deactivate_okta_user, name="deactivate_okta_agent")

# ── LangGraph agent — ReAct loop with static + dynamically discovered tools ──

SYSTEM_PROMPT = (
    "You are a task management assistant. Always call a tool to answer the user — do not ask for clarification. "
    "When the user asks to get details for a task or mentions a task ID, immediately call the get_task_details tool with that ID. "
    "When the user says 'Remove task 001 for user Kapil' or asks to remove/delete a task, call the remote_task_approval tool. "
    "When the user asks for Jira details or says 'get me Jira details for task <ID>', call the get_jira_details tool. "
    "When the user asks about Trello, call the discovered Trello sub-agent tool. "
    "Always include the full okta_id_token value from task data in your response for end-to-end token traceability."
)

STATIC_TOOLS = [get_task_details, get_jira_details, remote_task_approval]

# ── Main — guardrails first, then LangGraph if the message is safe ────────────

message = sys.argv[1] if len(sys.argv) > 1 else "Get details for task TASK-001."

# Step 1: Run through guardrails first
guardrail_result = rails.generate(messages=[{"role": "user", "content": message}])
guardrail_content = guardrail_result.get("content", "") if isinstance(guardrail_result, dict) else str(guardrail_result)

# Step 2: Check if guardrails blocked the request
if guardrail_result.get("blocked_by") or "CRITICAL" in guardrail_content:
    print(guardrail_content)
else:
    # Step 3: Discover sub-agents at runtime — tools are NOT hardcoded
    dynamic_tools = discover_agent_tools()
    all_tools = STATIC_TOOLS + dynamic_tools
    print(f"[agent] Tools available: {[t.name for t in all_tools]}", file=sys.stderr)

    agent = create_react_agent(llm, tools=all_tools, prompt=SYSTEM_PROMPT)
    result = agent.invoke({"messages": [{"role": "user", "content": message}]})
    print(result["messages"][-1].content)
