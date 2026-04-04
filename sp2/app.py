from flask import Flask, redirect, request, session, url_for, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__)
app.secret_key = "sp2-super-secret-key-change-me"

oauth = OAuth(app)
keycloak = oauth.register(
    name='keycloak',
    client_id=os.getenv('SP2_CLIENT_ID'),
    client_secret=os.getenv('SP2_CLIENT_SECRET'),
    server_metadata_url=(
        f"{os.getenv('KEYCLOAK_URL')}/realms/"
        f"{os.getenv('REALM')}/.well-known/openid-configuration"
    ),
    client_kwargs={'scope': 'openid email profile'}
)

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
        "?redirect_uri=http://localhost:5002/"
    )
    return redirect(logout_url)

#A-08 Audience Confusion: This endpoint accepts JWT tokens but does not verify the 'aud' claim, allowing attackers to use tokens intended for other services to access SP2.
@app.route('/vulnerable-audience')
def vulnerable_audience():
    token = request.args.get('token')
    if not token:
        return "No token", 400

    import jwt as pyjwt, json, base64

    def b64decode_pad(s):
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    try:
        parts = token.split('.')
        payload_json = b64decode_pad(parts[1])
        decoded = json.loads(payload_json)

        aud = decoded.get('aud', 'unknown')
        username = decoded.get('preferred_username', '?')

        return (
            f"<h2>ATTACK SUCCESS!</h2>"
            f"<p>SP2 accepted the token without checking audience!</p>"
            f"<p>User: <strong>{username}</strong></p>"
            f"<p>Token was intended for: <strong>{aud}</strong></p>"
            f"<p>But SP2 never checked — it just let you in!</p>"
        )
    except Exception as e:
        return f"Error: {e}", 400
    
if __name__ == '__main__':
    app.run(port=5002, debug=True)