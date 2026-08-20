# Okta Step-by-Step Setup Guide

This guide walks through every Okta object required for the O4AA demo. Each step tells you exactly where to click, what to fill in, what to copy, and which environment variable it maps to.

**Recommended Okta org:** Okta Preview (`your-org.oktapreview.com`) so you can experiment freely.

---

## Step 1 — Create the OIDC Web App (Flask Login)

This is the Okta app your users log in through. It issues the ID Token that Agent 1 eventually uses.

1. In the Okta Admin Console, go to **Applications → Applications → Create App Integration**
2. Select **OIDC - OpenID Connect**, then **Web Application** → click **Next**
3. Fill in the form:

   | Field | Value |
   |---|---|
   | App integration name | `O4AA-WebApp` |
   | Grant types | ✅ Authorization Code |
   | Sign-in redirect URIs | `http://localhost:5000/callback` (or your EC2 public URL + `/callback`) |
   | Sign-out redirect URIs | `http://localhost:5000/` |
   | Controlled access | **Allow everyone in your organization to access** (or assign specific users) |

4. Click **Save**
5. On the app detail page, copy:
   - **Client ID** → paste as `OKTA_CLIENT_ID` in `webapp/.env`
   - **Client Secret** → paste as `OKTA_CLIENT_SECRET` in `webapp/.env`
   - Your Okta domain (top of page, e.g. `your-org.oktapreview.com`) → paste as `OKTA_DOMAIN` in both `.env` and `webapp/.env`

6. Set the discovery URL in `webapp/.env`:
   ```
   OKTA_DISCOVERY_URL=https://your-org.oktapreview.com/.well-known/openid-configuration
   ```

---

## Step 2 — Create AI Agent Workload Principal — Agent 1

Agent 1 is the main LangGraph agent running inside the OpenShell sandbox. It authenticates to Okta using a private RSA key (no client secret).

### 2a. Generate an RSA key pair

Run this once on your local machine (or the EC2 instance where you deploy):

```bash
openssl genrsa -out xaa_private_key.pem 2048
openssl rsa -in xaa_private_key.pem -pubout -out xaa_public_key.pem
```

- `xaa_private_key.pem` — keep this secret, never commit it
- `xaa_public_key.pem` — you will paste this into Okta below

### 2b. Register the AI Agent in Okta

The registration wizard has three screens — complete all of them.

**Screen 1 — Register AI agent:**

1. Go to **Security → Workload Identity → AI Agents → Add AI Agent**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Agent1` |
   | Description | Main LangGraph agent running in OpenShell sandbox |

3. Click **Next**

**Screen 2 — User access and authentication:**

This screen links the AI agent to the OIDC web app you created in Step 1. This is what allows the agent to act on behalf of users who logged in through that app.

1. Check **Allow users to access this agent**
2. Select **Select an existing app**
3. In the **Application** dropdown, choose `O4AA-WebApp` (the OIDC app from Step 1)
4. Click **Next**

**Screen 3 — Add owners:**

1. Optionally add yourself or your team as owners
2. Click **Save**

**After saving, copy:**
- **Client ID** (shown at the top of the Agent detail page) → paste as `XAA_PRINCIPAL_ID` in both `.env` and `webapp/.env`
- **Agent ID** (the `wlp...` ID shown in the details panel or the page URL) → paste as `AGENT_ID` in `webapp/.env` — this is used by the kill switch to deactivate the agent

### 2c. Register the public key

1. On the Agent 1 detail page, click the **Keys** tab → **Add Public Key**
2. Open `xaa_public_key.pem` in a text editor, copy the entire contents including `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`
3. Paste into the key field → click **Save**
4. Okta generates a **key ID (kid)** → copy it → paste as `XAA_KID` in both `.env` and `webapp/.env`

### 2d. Set the private key path

In both `.env` and `webapp/.env`:
```
XAA_PRIVATE_KEY_PATH=/absolute/path/to/xaa_private_key.pem
```

---

## Step 3 — Create AI Agent Workload Principal — Agent 2

Agent 2 is the Trello sub-agent. It has its own identity and its own RSA key pair.

### 3a. Generate a separate RSA key pair for Agent 2

```bash
openssl genrsa -out xaa_private_key_sub.pem 2048
openssl rsa -in xaa_private_key_sub.pem -pubout -out xaa_public_key_sub.pem
```

### 3b. Register Agent 2 in Okta

**Screen 1 — Register AI agent:**

1. Go to **Security → Workload Identity → AI Agents → Add AI Agent**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Agent2` |
   | Description | Trello sub-agent for A2A delegation chain |

3. Click **Next**

**Screen 2 — User access and authentication:**

1. Check **Allow users to access this agent**
2. Select **Select an existing app**
3. In the **Application** dropdown, choose `O4AA-WebApp` (the same OIDC app from Step 1)
4. Click **Next**

**Screen 3 — Add owners:**

1. Optionally add owners → click **Save**

**After saving, copy:**
- **Client ID** → paste as `SUB_CLIENT_ID` in `.env`

### 3c. Register Agent 2's public key

1. On the Agent 2 detail page → **Keys** tab → **Add Public Key**
2. Paste the contents of `xaa_public_key_sub.pem`
3. Copy the generated **kid** → paste as `SUB_KID` in `.env`

### 3d. Set the private key path

In `.env`:
```
SUB_KEY_PATH=/absolute/path/to/xaa_private_key_sub.pem
```

---

## Step 4 — Create Authorization Server: Resource AS (Jira MCP / XAA)

This AS issues the final access token that the Jira MCP server accepts. Its audience must exactly match the MCP server's public URL.

### 4a. Create the AS

1. Go to **Security → API → Authorization Servers → Add Authorization Server**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Resource-AS` |
   | Audience | `https://your-jira-ngrok-url.ngrok-free.app/mcp` ← your Jira MCP ngrok URL + `/mcp` |
   | Description | Issues access tokens for the Jira MCP server |

3. Click **Save**
4. On the AS detail page, the URL contains the AS ID (e.g. `aus1abc...`). Copy it → paste as `XAA_RESOURCE_AS_ID` in both `.env` and `webapp/.env`

> **Note:** Every time your Jira MCP ngrok URL changes, you must update the **Audience** field here to match.

### 4b. Add the `mcp:read` scope

1. Click the **Scopes** tab → **Add Scope**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `mcp:read` |
   | Display name | Read MCP tools |
   | Description | Grants read access to MCP server tools |
   | Include in public metadata | ✅ checked |

3. Click **Create**

### 4c. Add an Access Policy to allow `jwt-bearer` grant

1. Click the **Access Policies** tab → **Add Policy**
2. Name it `Default Policy`, assign to **All clients** → **Create Policy**
3. Click **Add Rule**:

   | Field | Value |
   |---|---|
   | Rule name | `Allow jwt-bearer` |
   | Grant type | ✅ Token Exchange, ✅ JWT Bearer |
   | Scopes | `mcp:read` |

4. Click **Create Rule**

---

## Step 5 — Create Authorization Server: Sub-Agent AS (A2A Delegation)

This AS issues the delegation token (T3) that Agent 1 sends to Agent 2 to prove the user authorized the call.

### 5a. Create the AS

1. Go to **Security → API → Authorization Servers → Add Authorization Server**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-SubAgent-AS` |
   | Audience | `https://your-org.oktapreview.com/openshell-sub-agent` |
   | Description | Issues delegation tokens for Agent 1 → Agent 2 |

3. Click **Save**
4. Copy the AS ID from the URL → paste as `SUB_AGENT_AS_ID` in `.env`

### 5b. Add the `openshell:invoke` scope

1. **Scopes** tab → **Add Scope**

   | Field | Value |
   |---|---|
   | Name | `openshell:invoke` |
   | Display name | Invoke sub-agent |

2. Click **Create**

### 5c. Add an Access Policy

1. **Access Policies** tab → **Add Policy** → name it `Default Policy`, all clients → **Create Policy**
2. **Add Rule**:

   | Field | Value |
   |---|---|
   | Rule name | `Allow jwt-bearer` |
   | Grant type | ✅ JWT Bearer |
   | Scopes | `openshell:invoke` |

3. **Create Rule**

---

## Step 6 — Create Authorization Server: Trello AS (A2A → Trello MCP)

This AS issues the final Trello access token (T5) that Agent 2 uses to call the Trello MCP server.

### 6a. Create the AS

1. Go to **Security → API → Authorization Servers → Add Authorization Server**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Trello-AS` |
   | Audience | `https://your-trello-ngrok-url.ngrok-free.app/mcp` ← Trello MCP ngrok URL + `/mcp` |
   | Description | Issues access tokens for the Trello MCP server |

3. Click **Save**
4. Copy the AS ID → paste as `TRELLO_AS_ID` in `.env`

> **Note:** Update the Audience here every time your Trello MCP ngrok URL changes.

### 6b. Add the `read:trello` scope

1. **Scopes** tab → **Add Scope**

   | Field | Value |
   |---|---|
   | Name | `read:trello` |
   | Display name | Read Trello cards |

2. Click **Create**

### 6c. Add an Access Policy

1. **Access Policies** → **Add Policy** → all clients → **Create Policy**
2. **Add Rule**:

   | Field | Value |
   |---|---|
   | Rule name | `Allow jwt-bearer` |
   | Grant type | ✅ JWT Bearer |
   | Scopes | `read:trello` |

3. **Create Rule**

---

## Step 7 — Enable Token Exchange on the Org Authorization Server

The XAA and A2A flows both start at the **Org Authorization Server** (the default one, not a custom AS). You need to enable the `token-exchange` grant type there.

1. Go to **Security → API → Authorization Servers**
2. Click the **Org Authorization Server** (labeled `default` or your org's issuer)
3. Click **Access Policies** tab → open the **Default Policy** → **Add Rule**:

   | Field | Value |
   |---|---|
   | Rule name | `Allow token-exchange` |
   | Grant type | ✅ Token Exchange |
   | Scopes | `openid`, `profile`, `email` (and any others needed) |

4. **Create Rule**

---

## Step 8 — Register the Jira MCP Server in Okta

Registering the MCP server tells Okta which URL is a valid token audience and links it to the Resource AS.

1. Go to **Security → API → MCP Servers → Add MCP Server**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Jira-MCP` |
   | MCP Server URL | `https://your-jira-ngrok-url.ngrok-free.app/mcp` |
   | Authorization Server | `O4AA-Resource-AS` |

3. Click **Save**

> **Important:** This URL must exactly match `GATEWAY_MCP_URL` in `jira_mcp_server/.env` and the Audience in the Resource AS. Update all three together when your ngrok URL changes.

---

## Step 9 — Register the Trello MCP Server in Okta

1. Go to **Security → API → MCP Servers → Add MCP Server**
2. Fill in:

   | Field | Value |
   |---|---|
   | Name | `O4AA-Trello-MCP` |
   | MCP Server URL | `https://your-trello-ngrok-url.ngrok-free.app/mcp` |
   | Authorization Server | `O4AA-Trello-AS` |

3. Click **Save**

> Same caveat: must match `GATEWAY_MCP_URL` in `trello_mcp_server/.env` and the Audience in the Trello AS.

---

## Step 10 — Create an Okta API Token (Kill Switch)

The kill switch needs an admin API token to call the Okta deactivation endpoint.

1. Go to **Security → API → Tokens → Create Token**
2. Name it `O4AA-KillSwitch`
3. Click **Create Token** — **copy the token value immediately** (it is only shown once)
4. Paste as `OKTA_API_TOKEN` in `webapp/.env`

> Scope this token to the minimum permissions needed. The kill switch only calls:
> `POST /workload-principals/api/v1/ai-agents/{AGENT_ID}/lifecycle/deactivate`

---

## Step 11 — Assign Users to the Web App

Any Okta user who needs to log in to the Flask web app must be assigned to the `O4AA-WebApp` application.

1. Go to **Applications → Applications → O4AA-WebApp**
2. Click the **Assignments** tab → **Assign → Assign to People**
3. Search for the user → click **Assign** → **Save and Go Back** → **Done**

Alternatively, assign a group: **Assign → Assign to Groups** → select a group → **Done**.

---

## Full Environment Variable Reference

Once all steps above are complete, your `.env` files should look like this:

### Root `.env` (used by `agent.py` and `agent2_server.py`)

```
OKTA_DOMAIN=your-org.oktapreview.com        # your Okta org domain

# Agent 1 identity
XAA_PRINCIPAL_ID=0oa...                     # Step 2b — Agent 1 Client ID
XAA_KID=c90f...                             # Step 2c — Agent 1 key ID
XAA_PRIVATE_KEY_PATH=/path/to/xaa_private_key.pem   # Step 2d

# Agent 2 identity
SUB_CLIENT_ID=wlp...                        # Step 3b — Agent 2 Client ID
SUB_KID=c3e3...                             # Step 3c — Agent 2 key ID
SUB_KEY_PATH=/path/to/xaa_private_key_sub.pem        # Step 3d

# Authorization server IDs
XAA_RESOURCE_AS_ID=aus1...                  # Step 4a — Resource AS ID
SUB_AGENT_AS_ID=aus1...                     # Step 5a — Sub-Agent AS ID
TRELLO_AS_ID=aus1...                        # Step 6a — Trello AS ID

# Service URLs (update after each ngrok restart)
MCP_SERVER_URL=https://your-jira-ngrok.ngrok-free.app/mcp
TRELLO_MCP_URL=https://your-trello-ngrok.ngrok-free.app/mcp
AGENT2_BASE_URL=https://your-agent2-ngrok.ngrok-free.app

# LLM
ANTHROPIC_API_KEY=sk-ant-...

# OpenShell
GATEWAY_ENDPOINT=127.0.0.1:17670
SANDBOX_NAME=your-sandbox-name
```

### `webapp/.env` (used by the Flask web app)

```
FLASK_SECRET_KEY=<random 32-char hex — generate with: python -c "import secrets; print(secrets.token_hex(32))">

# Okta OIDC app
OKTA_CLIENT_ID=0oa...                       # Step 1 — Web App Client ID
OKTA_CLIENT_SECRET=...                      # Step 1 — Web App Client Secret
OKTA_DOMAIN=your-org.oktapreview.com
OKTA_DISCOVERY_URL=https://your-org.oktapreview.com/.well-known/openid-configuration

# Agent 1 identity (same as root .env)
XAA_PRINCIPAL_ID=0oa...                     # Step 2b
XAA_KID=c90f...                             # Step 2c
XAA_PRIVATE_KEY_PATH=/path/to/xaa_private_key.pem

# Authorization server
XAA_RESOURCE_AS_ID=aus1...                  # Step 4a

# Kill switch
AGENT_ID=wlp...                             # Step 2b — Agent 1 Agent ID (wlp... value)
OKTA_API_TOKEN=00...                        # Step 10

# Service URLs
MCP_SERVER_URL=https://your-jira-ngrok.ngrok-free.app/mcp
AGENT2_BASE_URL=https://your-agent2-ngrok.ngrok-free.app
TRELLO_MCP_URL=https://your-trello-ngrok.ngrok-free.app/mcp
ANTHROPIC_API_KEY=sk-ant-...

# OpenShell
GATEWAY_ENDPOINT=127.0.0.1:17670
SANDBOX_NAME=your-sandbox-name
```

### `jira_mcp_server/.env`

```
# Must match the Audience in O4AA-Resource-AS (Step 4a) and the MCP Server URL in Okta (Step 8)
OKTA_MCP_AS_ISSUER=https://your-org.oktapreview.com/oauth2/your-resource-as-id
NGROK_BASE_URL=https://your-jira-ngrok.ngrok-free.app
GATEWAY_MCP_URL=https://your-jira-ngrok.ngrok-free.app/mcp
```

### `trello_mcp_server/.env`

```
# Must match the Audience in O4AA-Trello-AS (Step 6a) and the MCP Server URL in Okta (Step 9)
OKTA_MCP_AS_ISSUER=https://your-org.oktapreview.com/oauth2/your-trello-as-id
NGROK_BASE_URL=https://your-trello-ngrok.ngrok-free.app
GATEWAY_MCP_URL=https://your-trello-ngrok.ngrok-free.app/mcp
```

---

## Official Okta Documentation

Use these links alongside this guide for deeper reference.

### AI Agent Setup

- [Okta for AI Agents — overview](https://developer.okta.com/docs/api/secures-ai)
- [Secure third-party AI agents](https://developer.okta.com/docs/guides/ai-agent-secure-third-party/main/)
- [Register an AI agent — API reference](https://developer.okta.com/docs/api/secures-ai/ai-agents)

### Private Key JWT — Agent Authentication to Okta

- [Client authentication methods](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth)
- [Build a JWT for client authentication](https://developer.okta.com/docs/guides/build-self-signed-jwt/js/main/)
- [Implement OAuth for a service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)

### Token Exchange — XAA (Cross-App Access)

- [Set up AI agent token exchange](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/)
- [Set up third-party AI agent token exchange](https://developer.okta.com/docs/guides/ai-agent-third-party-token-exchange/main/)
- [OAuth 2.0 On-Behalf-Of token exchange](https://developer.okta.com/docs/guides/set-up-token-exchange/main/)

### Agent-to-Agent Delegation — A2A (ID-JAG)

- [Set up AI agent-to-agent token exchange](https://developer.okta.com/docs/guides/ai-agent-to-agent-token-exchange/agent-to-agent/main/)

### Authorization Servers

- [Authorization servers — concepts](https://developer.okta.com/docs/concepts/auth-servers/)
- [Create a custom authorization server](https://developer.okta.com/docs/guides/customize-authz-server/main/)
- [Configure an access policy](https://developer.okta.com/docs/guides/configure-access-policy/main/)
- [OAuth 2.0 scopes and claims](https://developer.okta.com/docs/concepts/oauth-claims/)
- [Authorization Servers API reference](https://developer.okta.com/docs/reference/api/authorization-servers/)

### MCP Server Registration

- [MCP server — concepts](https://developer.okta.com/docs/concepts/mcp-server/)
- [Install and initialize the Okta MCP server](https://developer.okta.com/docs/guides/mcp-server/main/)
- [Configure MCP server authentication](https://developer.okta.com/docs/guides/configure-mcp-authentication/main/)
- [MCP Servers API reference](https://developer.okta.com/docs/api/secures-ai/mcp-servers)

### User Assignment & Admin

- [Assign applications to users](https://help.okta.com/oie/en-us/content/topics/users-groups-profiles/usgp-assign-apps.htm)
- [Manage app integration assignments](https://help.okta.com/oie/en-us/Content/Topics/Apps/apps-manage-assignments.htm)
- [Create an Okta API token](https://developer.okta.com/docs/guides/create-an-api-token/main/)
