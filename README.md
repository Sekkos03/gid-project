# GID — Digital Identity Management
## Practical Assignment 2025/2026 | Group 1

> **Master in Cybersecurity | Instituto Politécnico de Viana do Castelo**
> Protocol: OAuth 2.0 / OpenID Connect | IdP: Keycloak 24.5.6

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Running the System](#4-running-the-system)
5. [Test Accounts](#5-test-accounts)
6. [Project Structure](#6-project-structure)
7. [Attack Scripts](#7-attack-scripts)
   - [A-01 Replay Attack](#a-01-replay-attack)
   - [A-05 JWT Algorithm Confusion](#a-05-jwt-algorithm-confusion)
   - [A-08 Audience Confusion](#a-08-audience-confusion)
8. [Running Mitigations](#8-running-mitigations)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Project Overview

This project implements a Federated Identity Management (FIM) system following the **Build > Attack > Defend** methodology.

| Phase | Description |
|-------|-------------|
| **Build** | A working SSO system with Keycloak (IdP) and two Flask apps (SP1, SP2) |
| **Attack** | Three real attacks demonstrated against the system |
| **Defend** | Each attack mitigated with working code and protocol-level explanation |

**Assigned attacks:**
- `A-01` — Replay Attack on Authentication Token
- `A-05` — JWT Algorithm Confusion (RS256 → HS256)
- `A-08` — Insufficient Audience Validation at SP

---

## 2. System Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Java | 17+ (LTS) | Required to run Keycloak |
| Python | 3.10+ | For Flask apps |
| Keycloak | 24.5.6 | Download from keycloak.org |
| pip packages | — | See below |

### Python dependencies

```bash
pip install flask authlib python-dotenv requests PyJWT cryptography gunicorn
```

---

## 3. Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/Sekkos03/gid-project.git
cd gid-project
```

### Step 2 — Download and extract Keycloak

```bash
# Download from https://www.keycloak.org/downloads
# Extract to a folder e.g. ~/keycloak or C:\keycloak
```

### Step 3 — Configure environment variables

Copy the example env file and fill in your Keycloak client secrets:

```bash
cp .env.example .env
```

Edit `.env`:

```env
KEYCLOAK_URL=http://localhost:8080
REALM=gid-realm

SP1_CLIENT_ID=sp1-app
SP1_CLIENT_SECRET=PASTE_YOUR_SP1_SECRET_HERE

SP2_CLIENT_ID=sp2-app
SP2_CLIENT_SECRET=PASTE_YOUR_SP2_SECRET_HERE
```

> **Where to find the client secrets:** Keycloak Admin → Clients → sp1-app → Credentials tab → copy Client Secret

### Step 4 — Configure Keycloak

Start Keycloak (see Section 4), then complete this setup in the admin console at `http://localhost:8080/admin`:

1. **Create Realm** → name: `gid-realm`
2. **Create Roles** → `admin`, `user`
3. **Create Users:**
   - `sekou` — password: `sekou123`, role: `admin`
   - `bob` — password: `bob123`, role: `user`
4. **Create Clients:**
   - `sp1-app` — redirect URI: `http://localhost:5001/*`
   - `sp2-app` — redirect URI: `http://localhost:5002/*`
5. **Add Role Mapper** to each client:
   - Client Scopes → `sp1-app-dedicated` → Add mapper → By configuration → **User Realm Role**
   - Name: `realm-roles`, Token Claim Name: `realm_access.roles`, Add to ID token: ON, Add to access token: ON

---

## 4. Running the System

Open **three separate terminals** and run each command:

### Terminal 1 — Start Keycloak

```bash
# Linux / macOS
cd ~/gid-project/keycloak/keycloak-26.5.6
bin/kc.sh start-dev

# Windows
cd C:\gid-project\keycloak\keycloak-26.5.6
bin\kc.bat start-dev
```

Wait until you see: `Keycloak 24.5.6 on JVM (powered by Quarkus) started`

### Terminal 2 — Start SP1

```bash
cd gid-project/sp1
python app.py
```

SP1 available at: **http://localhost:5001**

### Terminal 3 — Start SP2

```bash
cd gid-project/sp2
python app.py
```

SP2 available at: **http://localhost:5002**

### Verify SSO is working

1. Go to `http://localhost:5001` → click **Login with SSO**
2. Log in as `sekou / sekou123`
3. You should see the Admin Panel (role-based content)
4. Click **Go to App 2** → you should be logged in automatically (no login prompt)
5. That confirms SSO is working ✓

---

## 5. Test Accounts

| Username | Password | Role | What they see |
|----------|----------|------|---------------|
| `sekou` | `sekou123` | admin | Admin panel + full access |
| `bob` | `bob123` | user | Regular user panel only |

---

## 6. Project Structure

```
gid-project/
│
├── keycloak/
│   └── keycloak-26.5.6/
│
├── sp1/
│   ├── app.py                  # SP1 Flask application
│   └── templates/
│
├── sp2/
│   ├── app.py                  # SP2 Flask application
│   └── templates/
│       ├── home.html
│       └── dashboard.html
│
├── forge_token.py              # Forges JWT with HS256 (A-05 attack script)
├── get_pubkey.py               # Fetches Keycloak public key (used in A-05)
├── keycloak_pub.pem
├── .env
├── .gitattributes
└── README.md
```

---

## 7. Attack Scripts

> ⚠️ **Important:** All attacks must be executed **only** in this local controlled environment. Never run these against third-party systems.

---

### A-01 Replay Attack

**What it does:** Intercepts a valid login token and reuses it after the user has logged out.

#### Step 1 — Add the vulnerable route to SP1

Make sure `sp1/app.py` contains the `/vulnerable-login` route (already included).

#### Step 2 — Get a token

Start all services, log in as sekou on SP1, then visit:

```
http://localhost:5001/show-token
```

Copy the entire JWT string shown on the page.

#### Step 3 — Logout

Click Logout on SP1.

#### Step 4 — Replay the token

Paste the token into this URL and open it in a fresh browser window:

```
http://localhost:5001/vulnerable-login?token=PASTE_TOKEN_HERE
```

**Expected result:** `Logged in as sekou (REPLAYED!)` — attack successful ✓

#### Step 5 — Capture evidence

- Screenshot of the token at `jwt.io` (showing `jti` and `exp`)
- Screenshot of the logout confirmation
- Screenshot of the replay success response

---

### A-05 JWT Algorithm Confusion

**What it does:** Forges a completely fake JWT signed with the public key using HS256, bypassing the need for Keycloak's private key.

#### Step 1 — Fetch the public key

```bash
cd attacks/
python get_pubkey.py
```

This saves `keycloak_pub.pem` in the current directory.

**Expected output:**

```
Public key PEM:
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkq...
-----END PUBLIC KEY-----
Saved to keycloak_pub.pem
```

#### Step 2 — Forge a token

```bash
python forge_token.py
```

**Expected output:**

```
Forged token: eyJhbGciOiJIUzI1NiJ9...

Attack URL:
http://localhost:5001/vulnerable-jwt?token=eyJhbGci...
```

#### Step 3 — Execute the attack

Copy the Attack URL from the output and open it in your browser.

**Expected result:** `Access granted to evil-admin via HS256!` — attack successful ✓

#### Step 4 — Capture evidence

- Screenshot of `get_pubkey.py` output (public key)
- Screenshot of `forge_token.py` output
- Screenshot of `jwt.io` showing the forged payload (`evil-admin`, role: `admin`)
- Screenshot of SP1 accepting the forged token

---

## 8. Running Mitigations

Each attack has a corresponding secured endpoint. After demonstrating each attack, show it is blocked:

| Attack | Vulnerable route | Secure route | Expected response when blocked |
|--------|-----------------|--------------|-------------------------------|
| A-01 | `/vulnerable-login` | `/secure-login` | `403 Token already used` |
| A-05 | `/vulnerable-jwt` | `/secure-jwt` | `403 Algorithm not allowed` |

Replay each attack using the secure URL to demonstrate the mitigation works.

---

## 9. Troubleshooting

| Problem | Solution |
|---------|----------|
| `java: command not found` | Install Java 17+ from adoptium.net |
| Keycloak won't start | Check no other process is on port 8080: `lsof -i :8080` |
| `SP1_CLIENT_SECRET` missing error | Make sure `.env` file exists and has the correct secrets from Keycloak |
| SSO not working between SP1 and SP2 | Check that both clients have the realm-roles mapper configured |
| Token decode fails | Ensure `PyJWT>=2.0` is installed: `pip install --upgrade PyJWT` |
| `keycloak_pub.pem not found` | Run `python attacks/get_pubkey.py` first before the A-05 attack |
| Redirect URI mismatch error | In Keycloak, verify the Valid redirect URIs match exactly including the `/*` wildcard |

---

*Group 1 | GID 2025/2026 | Instituto Politécnico de Viana do Castelo*
