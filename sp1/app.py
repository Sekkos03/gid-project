from flask import Flask, redirect, request, session, url_for, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__)
app.secret_key = "sp1-super-secret-key-change-me"

oauth = OAuth(app)
keycloak = oauth.register(
    name='keycloak',
    client_id=os.getenv('SP1_CLIENT_ID'),
    client_secret=os.getenv('SP1_CLIENT_SECRET'),
    server_metadata_url=(
        f"{os.getenv('KEYCLOAK_URL')}/realms/"
        f"{os.getenv('REALM')}/.well-known/openid-configuration"
    ),
    client_kwargs={'scope': 'openid email profile'}
)

# ---- MITIGATION A-01: jti replay store (comment out to re-enable vulnerability) ----
used_jtis = set()
# ------------------------------------------------------------------------------------


@app.route('/')
def home():
    return render_template('home.html', user=session.get('user'))

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return keycloak.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = keycloak.authorize_access_token()
    session['user'] = token.get('userinfo')
    session['token'] = token
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if not session.get('user'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session.get('user'))

@app.route('/logout')
def logout():
    session.clear()
    logout_url = (
        f"{os.getenv('KEYCLOAK_URL')}/realms/{os.getenv('REALM')}"
        "/protocol/openid-connect/logout"
        "?redirect_uri=http://localhost:5001/"
    )
    return redirect(logout_url)
#A-01 Replay Attack: This endpoint allows an attacker to replay a previously captured JWT token without any verification, leading to unauthorized access.
@app.route('/vulnerable-login')
def vulnerable_login():
    token = request.args.get('token')
    if not token:
        return "No token provided", 400
    try:
        import jwt as pyjwt
        import requests as pyrequests

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False,
                     "verify_exp": False},
        )
                # ---- MITIGATION A-01: jti replay check (comment out block to re-enable vulnerability) ----
        jti = decoded.get('jti')
        if not jti:
            return "Token has no jti claim — rejected", 403
        if jti in used_jtis:
            return "Token already used — replay attack detected", 403
        used_jtis.add(jti) 
        # ---- MITIGATION A-01: token introspection (comment out block to re-enable vulnerability) ----
        introspect_url = (
            f"{os.getenv('KEYCLOAK_URL')}/realms/{os.getenv('REALM')}"
            "/protocol/openid-connect/token/introspect"
        )
        introspect_resp = pyrequests.post(introspect_url, data={
            'token': token,
            'client_id': os.getenv('SP1_CLIENT_ID'),
            'client_secret': os.getenv('SP1_CLIENT_SECRET'),
        })
        introspect_data = introspect_resp.json()
        if not introspect_data.get('active', False):
            return "Token is no longer active (session ended or expired) — rejected", 403
        # ---- END MITIGATION ----
        # -------------------------------------------------------------------------------------------

        session['user'] = decoded
        return f"Logged in as {decoded.get('preferred_username')} (REPLAYED!)"
    except Exception as e:
        return f"Token error: {e}", 400

@app.route('/show-token')
def show_token():
    token = session.get('token', {})
    return token.get('access_token', 'no token')
#----------------------------------------------

#A-02 Algorithm Confusion: This endpoint is vulnerable to algorithm confusion attacks, allowing an attacker to forge a JWT token using a weaker algorithm (e.g., HS256) and gain unauthorized access.
@app.route('/vulnerable-jwt')
def vulnerable_jwt():
    token = request.args.get('token')
    if not token:
        return "No token", 400

    import os, json, base64, hmac, hashlib
    import jwt as pyjwt

    base_dir = os.path.dirname(os.path.abspath(__file__))
    pem_path = os.path.join(base_dir, '..', 'keycloak_pub.pem')

    header = pyjwt.get_unverified_header(token)
    alg = header.get('alg', 'RS256')

    # ---- MITIGATION A-02: algorithm allowlist (comment out block to re-enable vulnerability) ----
    ALLOWED_ALGORITHMS = {'RS256'}
    if alg not in ALLOWED_ALGORITHMS:
        return (
            f"Token rejected: algorithm '{alg}' is not permitted. "
            f"Only {ALLOWED_ALGORITHMS} are accepted."
        ), 401
    # ---- END MITIGATION A-02 ----

    try:
        with open(pem_path, 'rb') as f:
            pem_data = f.read()

        if alg == 'HS256':
            # Manually verify HS256 using the public key as secret
            # This simulates a vulnerable server that trusts the alg header
            parts = token.split('.')
            if len(parts) != 3:
                return "Invalid token format", 401

            signing_input = f"{parts[0]}.{parts[1]}".encode()

            # Add padding back to base64
            def b64decode_pad(s):
                s += '=' * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s)

            # Recompute the signature using public key as HMAC secret
            expected_sig = hmac.new(
                pem_data,
                signing_input,
                hashlib.sha256
            ).digest()

            actual_sig = b64decode_pad(parts[2])

            # Compare signatures (this is the vulnerable check)
            if hmac.compare_digest(expected_sig, actual_sig):
                payload_json = b64decode_pad(parts[1])
                decoded = json.loads(payload_json)
                session['user'] = decoded
                return (
                    f"<h2>ATTACK SUCCESS!</h2>"
                    f"Access granted to <strong>{decoded.get('preferred_username')}</strong>"
                    f" via algorithm: <strong>{alg}</strong><br>"
                    f"This user does not exist in Keycloak!"
                )
            else:
                return "Signature mismatch", 401

        else:
            # Normal RS256 path
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            key = load_pem_public_key(pem_data, backend=default_backend())

            decoded = pyjwt.decode(
                token, key,
                algorithms=['RS256'],
                options={"verify_aud": False}
            )
            session['user'] = decoded
            return f"Access granted to {decoded.get('preferred_username')} via {alg}!"

    except Exception as e:
        return f"Token rejected: {e}", 401
if __name__ == '__main__':
    app.run(port=5001, debug=True)

