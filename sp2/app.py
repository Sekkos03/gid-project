from flask import Flask, redirect, session, url_for, render_template
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

if __name__ == '__main__':
    app.run(port=5002, debug=True)