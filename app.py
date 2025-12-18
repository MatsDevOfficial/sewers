import json
import os
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, session, redirect, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
import db

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = 'secret'
db.init_db()

with open('config.json', 'r') as f:
    config = json.load(f)

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
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
    redirect_uri = request.url_root.rstrip('/') + '/auth/callback'
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': redirect_uri,
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
        'redirect_uri': request.url_root.rstrip('/') + '/auth/callback',
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
    user_id = db.insert_user(email, nickname, slack_id)
    session['user'] = nickname
    session['id'] = user_id
    session['slack_id'] = slack_id
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        slack_id = session['slack_id']
        hackatime_response = requests.get(f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/stats?limit=1000&features=projects&start_date=2025-12-16").json()
        projects = db.get_projects(session['id'])
        hackatime_projects = hackatime_response.get('data', {}).get('projects', [])
        projects_with_hours = []
        for proj in projects:
            hours = next((hp.get('text', '0') for hp in hackatime_projects if hp.get('name') == proj[5]), '0')
            projects_with_hours.append(proj + (hours,))
        return render_template('dashboard.html', name=session['user'], config=config, hackatime=hackatime_response, projects=projects_with_hours)
    else:
        return redirect(url_for('login'))

@app.route('/create_project', methods=['POST'])
def create_project():
    if 'user' not in session:
        return redirect(url_for('login'))
    title = request.form.get('title')
    description = request.form.get('description')
    demo_link = request.form.get('demoLink')
    github_link = request.form.get('githubLink')
    hackatime_project = request.form.get('hours')
    user_id = session['id']
    db.insert_project(user_id, title, description, demo_link, github_link, hackatime_project)
    return redirect(url_for('dashboard'))

@app.route('/badbad')
def badbad():
    return "You are not YSWS eligible to access this."

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)