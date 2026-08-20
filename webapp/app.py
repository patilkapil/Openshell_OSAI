# Flask Web App — user-facing UI and orchestration layer.
#
# Responsibilities:
#   - Okta OIDC login via Authlib (authorization code + private_key_jwt)
#   - Stores the user's ID Token in the Flask session after login
#   - On each chat message, execs agent.py inside the OpenShell sandbox via the SDK
#   - Injects the ID Token and all required env vars into the sandbox at exec time
#   - Reads agent stdout as the response and stderr for debug/guardrail signals
#   - Kill switch: if the sandbox agent signals a violation, calls Okta to deactivate the agent

from flask import Flask, session, redirect, url_for, request, render_template
from authlib.integrations.flask_client import OAuth
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dotenv import load_dotenv
import openshell
import requests
import jwt
import uuid
import time
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

CLIENT_ID   = os.environ["OKTA_CLIENT_ID"]
OKTA_DOMAIN = os.environ.get("OKTA_DOMAIN", "")
XAA_KID     = os.environ.get("XAA_KID", "")
_key_path   = os.environ.get("XAA_PRIVATE_KEY_PATH", "")

with open(_key_path, "rb") as _f:
    _private_key = load_pem_private_key(_f.read(), password=None)


def _build_client_assertion():
    token_endpoint = f"https://{OKTA_DOMAIN}/oauth2/v1/token"
    now = int(time.time())
    return jwt.encode({
        "iss": CLIENT_ID, "sub": CLIENT_ID,
        "aud": token_endpoint,
        "iat": now, "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }, _private_key, algorithm="RS256", headers={"kid": XAA_KID})


# Authlib handles the OIDC redirect and state/nonce — token exchange is done manually
# below in /callback using private_key_jwt (no client secret)
oauth = OAuth(app)
okta = oauth.register(
    name="okta",
    client_id=CLIENT_ID,
    client_secret=os.environ.get("OKTA_CLIENT_SECRET", ""),
    server_metadata_url=os.environ["OKTA_DISCOVERY_URL"],
    client_kwargs={"scope": "openid profile email"},
)

SANDBOX_NAME = os.environ.get("SANDBOX_NAME", "")
AGENT_ID     = os.environ.get("AGENT_ID", "")


def deactivate_okta_agent():
    """Called by the Flask backend when the sandbox guardrail signals a violation.
    Runs on the host which has full internet access to reach Okta."""
    okta_domain = os.environ.get("OKTA_DOMAIN", "")
    api_token   = os.environ.get("OKTA_API_TOKEN", "")
    if not api_token or not AGENT_ID:
        print("Backend: Missing OKTA_API_TOKEN or AGENT_ID, cannot deactivate.")
        return
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    url = f"https://{okta_domain}/workload-principals/api/v1/ai-agents/{AGENT_ID}/lifecycle/deactivate"
    try:
        resp = requests.post(url, headers=headers, json={})
        print(f"Backend: Deactivated Okta agent {AGENT_ID} ({resp.status_code})")
    except Exception as e:
        print(f"Backend: Deactivation error — {e}")


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session["user"], access_token=session.get("access_token"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login/okta")
def login_okta():
    return okta.authorize_redirect(redirect_uri=url_for("callback", _external=True))


@app.route("/callback")
def callback():
    # Exchanges the Okta authorization code for tokens using private_key_jwt auth.
    # Stores the ID Token in session — this is what gets injected into the sandbox.
    code = request.args.get("code")
    token_endpoint = f"https://{OKTA_DOMAIN}/oauth2/v1/token"
    resp = requests.post(token_endpoint, data={
        "grant_type":            "authorization_code",
        "code":                  code,
        "redirect_uri":          url_for("callback", _external=True),
        "client_id":             CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _build_client_assertion(),
    })
    resp.raise_for_status()
    token_data = resp.json()
    id_token = token_data.get("id_token", "")
    userinfo = jwt.decode(id_token, options={"verify_signature": False}) if id_token else {}
    session["user"] = userinfo
    session["access_token"] = token_data.get("access_token", "")
    session["id_token"] = id_token
    print(f"[LOGIN] User: {userinfo.get('email')}")
    print(f"[LOGIN] ID Token: {id_token}")
    print(f"[LOGIN] Access Token: {token_data.get('access_token', '')}")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    # Finds the named sandbox, execs agent.py inside it with the user message and
    # all required env vars (ID Token, Okta config, MCP URLs, private key path).
    # Agent stdout is returned as the chat response; stderr is logged to the console.
    user_message = request.form.get("message", "").strip()
    if not user_message:
        return render_template("index.html", user=session["user"], error="Message cannot be empty.")

    client = openshell.SandboxClient(
        os.environ.get("GATEWAY_ENDPOINT")
    )

    sandboxes = client.list(workspace="default")
    sandbox = next((s for s in sandboxes if s.name == SANDBOX_NAME), None)

    if not sandbox:
        return render_template("index.html", user=session["user"], error=f"Sandbox '{SANDBOX_NAME}' not found.")

    result = client.exec(
        sandbox.id,
        command=["/sandbox/.venv312/bin/python", "/sandbox/agent.py", user_message],
        env={
            "OKTA_ID_TOKEN":        session.get("id_token", ""),
            "OKTA_USER_EMAIL":      session["user"].get("email", ""),
            "OKTA_API_TOKEN":       os.environ.get("OKTA_API_TOKEN", ""),
            "OKTA_DOMAIN":          os.environ.get("OKTA_DOMAIN", ""),
            "AGENT_ID":             os.environ.get("AGENT_ID", ""),
            "XAA_PRINCIPAL_ID":     CLIENT_ID,
            "XAA_RESOURCE_AS_ID":   os.environ.get("XAA_RESOURCE_AS_ID", ""),
            "XAA_KID":              os.environ.get("XAA_KID", ""),
            "XAA_PRIVATE_KEY_PATH": os.environ.get("XAA_PRIVATE_KEY_PATH", ""),
            "MCP_SERVER_URL":       os.environ.get("MCP_SERVER_URL", ""),
            "AGENT2_BASE_URL":      os.environ.get("AGENT2_BASE_URL", ""),
        },
        timeout_seconds=120
    )

    agent_output = result.stdout.strip()
    agent_stderr = result.stderr.strip()

    # Log stderr to Flask console always (visible in EC2 terminal)
    if agent_stderr:
        print(f"[AGENT STDERR]\n{agent_stderr}")

    # Guardrail handoff: sandbox detected a violation — backend deactivates the agent
    if "CRITICAL: Security violation detected" in agent_output:
        deactivate_okta_agent()

    if result.exit_code == 0:
        response = agent_output
    else:
        # Show both stdout and stderr so errors are visible in the chat
        response = agent_output or f"[Agent error]\n{agent_stderr}"

    return render_template("index.html", user=session["user"], response=response, message=user_message, debug_log=agent_stderr)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
