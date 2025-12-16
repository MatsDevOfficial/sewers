import json
import os
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, session, redirect, request, url_for
import db

load_dotenv()

app = Flask(__name__)
app.secret_key = 'secret'
db.init_db()

with open('config.json', 'r') as f:
    config = json.load(f)

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/auth/callback' 
AUTH_URL = 'https://auth.hackclub.com/oauth/authorize'
TOKEN_URL = 'https://auth.hackclub.com/oauth/token'
JWKS_URL = 'https://auth.hackclub.com/oauth/discovery/keys'
USERINFO_URL = 'https://auth.hackclub.com/oauth/userinfo'


@app.route('/')
def home():
    with open('config.json', 'r') as f:
        config = json.load(f)
    return render_template('index.html', config=config)

@app.route('/login')
def login():
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid profile email slack_id verification_status'
    }
    auth_url = f"{AUTH_URL}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code received", 400

    token_data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'code': code,
        'grant_type': 'authorization_code'
    }
    token_response = requests.post(TOKEN_URL, data=token_data)
    if token_response.status_code != 200:
        return "Error: Failed to get tokens", 400

    tokens = token_response.json()
    access_token = tokens.get('access_token')
    if not access_token:
        return "Error: No access token", 400

    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(USERINFO_URL, headers=headers)
    if userinfo_response.status_code != 200:
        return "Error: Failed to get user info", 400

    userinfo = userinfo_response.json()
    if userinfo.get('verification_status') != 'verified' or not userinfo.get('ysws_eligible'):
        return redirect('/badbad')

    email = userinfo.get('email')
    nickname = userinfo.get('nickname') or userinfo.get('name')
    slack_id = userinfo.get('slack_id')
    db.insert_user(email, nickname, slack_id)
    session['user'] = nickname
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', name=session['user'], config=config)
    else:
        return redirect(url_for('login'))

@app.route('/badbad')
def badbad():
    return "You are not eligible to access this application."

if __name__ == '__main__':
    app.run(debug=True)