import os
from flask import Flask, render_template, redirect, request, session, jsonify, url_for
from urllib.parse import urlparse
import requests
from functools import wraps
from datetime import timedelta
import db
import admin_db
import slack

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET', os.urandom(24))

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTH_URL = 'https://auth.hackclub.com/oauth/authorize'
TOKEN_URL = 'https://auth.hackclub.com/oauth/token'
JWKS_URL = 'https://auth.hackclub.com/oauth/discovery/keys'
USERINFO_URL = 'https://auth.hackclub.com/oauth/userinfo'

ADMIN_EMAILS = os.getenv('ORGS', '').split(',')
REVIEWER_EMAILS = os.getenv('ORGS', '').split(',')

db.init_db()
admin_db.init_db()

@app.route('/')
def index():
    faqs = admin_db.get_all_faqs()
    rewards = admin_db.get_all_rewards()
    return render_template('index.html', faqs=faqs, rewards=rewards)

@app.route('/s/<uuid_str>')
def ship_redirect(uuid_str):
    user = db.get_user_by_uuid(uuid_str)
    if not user:
        return render_template('unauthorized.html'), 404
    
    projects = db.get_user_projects(user['id'], status='Shipped')
    if projects:
        # Redirect to the most recent shipped project
        return redirect(projects[0]['demo_link'])
    
    return redirect(f"/profile/{uuid_str}")

@app.route('/profile/<uuid_str>')
def public_profile(uuid_str):
    user = db.get_user_by_uuid(uuid_str)
    if not user:
        return render_template('unauthorized.html'), 404
    
    projects = db.get_user_projects(user['id'])
    return render_template('public_profile.html', user=user, projects=projects)

@app.route('/login')
def login():
    parsed = urlparse(request.url_root)
    if parsed.hostname not in ['localhost', '127.0.0.1', '0.0.0.0']:
        redirect_uri = 'https://' + parsed.netloc + '/auth/callback'
    else:
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

    parsed = urlparse(request.url_root)
    if parsed.hostname not in ['localhost', '127.0.0.1', '0.0.0.0']:
        redirect_uri = 'https://' + parsed.netloc + '/auth/callback'
    else:
        redirect_uri = request.url_root.rstrip('/') + '/auth/callback'
    
    token_data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': redirect_uri,
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
        return redirect('/unauthorized')

    email = userinfo.get('email')
    nickname = userinfo.get('nickname') or userinfo.get('name')
    slack_id = userinfo.get('slack_id')

    user_id = db.get_or_create_user(email, nickname, slack_id)
    
    session['user_id'] = user_id
    session['slack_id'] = slack_id
    session['email'] = email
    session['nickname'] = nickname
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html'), 403

@app.route('/dash')
def dashboard():
    if 'user_id' not in session:
        print('not in session')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    if 'slack_id' not in session:
        return jsonify({'error': 'abc'}), 401
    
    if session['slack_id'] not in ADMIN_EMAILS:
        return jsonify({'error': '123'}), 403
    
    return render_template('admin.html')

@app.route('/reviewer')
def reviewer():
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in REVIEWER_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return render_template('reviewer.html')

@app.route('/api/projects', methods=['GET'])
def get_projects():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    slack_id = session['slack_id']
    hackatime_response = requests.get(f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/stats?limit=1000&features=projects&start_date=2025-12-16").json()
    projects = db.get_user_projects(session['user_id'])
    hackatime_projects = hackatime_response.get('data', {}).get('projects', [])
    projects_with_hours = []
    
    for proj in projects:
        project_id = proj['id']
        hackatime_project_names = proj['hackatime_project'] if proj['hackatime_project'] else ''
        
        total_seconds = 0
        if hackatime_project_names:
            project_names = [name.strip() for name in hackatime_project_names.split(',')]
            for project_name in project_names:
                for hp in hackatime_projects:
                    if hp.get('name') == project_name:
                        total_seconds += hp.get('total_seconds', 0)
                        break
        
        total_hours = total_seconds / 3600.0
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        digital_format = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        stored_hours = proj['hours'] if proj['hours'] else 0
        if abs(stored_hours - total_hours) > 0.01:
            db.update_project_hours(project_id, total_hours)
            proj['hours'] = total_hours
        
        project_with_hours = dict(proj)
        project_with_hours['digital_hours'] = digital_format
        projects_with_hours.append(project_with_hours)
    
    return jsonify({'projects': projects_with_hours})


@app.route('/api/hackatime')
def get_hackatime():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    slack_id = session['slack_id']
    hackatime_response = requests.get(f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/stats?limit=1000&features=projects&start_date=2025-12-16").json()
    return jsonify(hackatime_response)

@app.route('/api/projects', methods=['POST'])
def create_project():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    project_id = db.create_project(
        user_id=session['user_id'],
        title=data.get('title'),
        description=data.get('description'),
        demo_link=data.get('demo_link'),
        github_link=data.get('github_link'),
        hackatime_project=data.get('hackatime_project')
    )
    
    # Notify Slack
    project = {
        'title': data.get('title'),
        'description': data.get('description'),
        'slack_id': session['slack_id']
    }
    slack.project_created(project)
    
    return jsonify({'success': True, 'project_id': project_id}), 201

@app.route('/api/projects/<int:project_id>', methods=['GET'])
def get_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    project = db.get_project_by_id(project_id)
    if not project:
        return jsonify({'error': 'Project not found'}), 404
    
    if project['user_id'] != session['user_id'] and session['email'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(project)

@app.route('/api/projects/<int:project_id>', methods=['PUT'])
def update_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not db.check_project_owner(project_id, session['user_id']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    success = db.update_project(
        project_id=project_id,
        title=data.get('title'),
        description=data.get('description'),
        demo_link=data.get('demo_link'),
        github_link=data.get('github_link'),
        hackatime_project=data.get('hackatime_project'),
        hours=data.get('hours'),
        status=data.get('status')
    )
    
    return jsonify({'success': success})

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not db.check_project_owner(project_id, session['user_id']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    success = db.delete_project(project_id)
    return jsonify({'success': success})

@app.route('/api/projects/<int:project_id>/status', methods=['PATCH'])
def update_project_status(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = db.get_user_by_id(session['user_id'])
    if not user or user['email'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    status = data.get('status')
    
    if not status:
        return jsonify({'error': 'Status required'}), 400
    
    success = db.update_project_status(project_id, status)
    return jsonify({'success': success})

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = db.get_user_by_id(session['user_id'])
    project_count = db.count_projects(session['user_id'])
    total_hours = db.get_total_hours(session['user_id'])
    
    return jsonify({
        'user': user,
        'project_count': project_count,
        'total_hours': total_hours,
        'ship_link': f"{request.url_root.rstrip('/')}/s/{user['ship_uuid']}" if user.get('ship_uuid') else None
    })

@app.route('/api/user/profile', methods=['PUT'])
def update_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    success = db.update_user(
        user_id=session['user_id'],
        nickname=data.get('nickname'),
        slack_id=data.get('slack_id')
    )
    
    if success and data.get('nickname'):
        session['nickname'] = data.get('nickname')
    
    return jsonify({'success': success})
        
@app.route('/api/faqs', methods=['GET'])
def get_faqs():
    faqs = admin_db.get_all_faqs()
    return jsonify({'faqs': faqs})

@app.route('/api/admin/faqs', methods=['POST'])
def create_faq_endpoint():
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
        
    
    data = request.get_json()
    question = data.get('question')
    answer = data.get('answer')
    
    if not question or not answer:
        return jsonify({'error': 'Question and answer required'}), 400
    
    faq_id = admin_db.create_faq(question, answer)
    return jsonify({'success': True, 'faq_id': faq_id}), 201

@app.route('/api/admin/faqs/<int:faq_id>', methods=['DELETE'])
def delete_faq_endpoint(faq_id):
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    success = admin_db.delete_faq(faq_id)
    return jsonify({'success': success})

@app.route('/api/rewards', methods=['GET'])
def get_rewards():
    rewards = admin_db.get_all_rewards()
    return jsonify({'rewards': rewards})

@app.route('/api/admin/rewards', methods=['POST'])
def create_reward_endpoint():
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    cost = data.get('cost')
    image_url = data.get('image_url')
    
    if not all([name, description, cost, image_url]):
        return jsonify({'error': 'All fields required'}), 400
    
    try:
        cost = float(cost)
    except (ValueError, TypeError):
        return jsonify({'error': 'Cost must be a number'}), 400
    
    reward_id = admin_db.create_reward(name, description, cost, image_url)
    return jsonify({'success': True, 'reward_id': reward_id}), 201

@app.route('/api/admin/rewards/<int:reward_id>', methods=['DELETE'])
def delete_reward_endpoint(reward_id):
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in ADMIN_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    success = admin_db.delete_reward(reward_id)
    return jsonify({'success': success})

@app.route('/api/reviewer/projects', methods=['GET'])
def get_reviewer_projects():
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in REVIEWER_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    projects = db.get_all_projects()
    return jsonify({'projects': projects})

@app.route('/api/reviewer/projects/<int:project_id>/approve', methods=['POST'])
def approve_project(project_id):
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in REVIEWER_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    project = db.get_project_by_id(project_id)
    if not project:
        return jsonify({'error': 'Project not found'}), 404
    
    user = db.get_user_by_id(project['user_id'])
    if user:
        project['slack_id'] = user['slack_id']
        project['nickname'] = user['nickname']
    
    success = db.update_project_status(project_id, 'Shipped')
    
    if success:
        slack.project_shipped(project)
    
    return jsonify({'success': success})

@app.route('/api/reviewer/projects/<int:project_id>/reject', methods=['POST'])
def reject_project(project_id):
    if 'slack_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['slack_id'] not in REVIEWER_EMAILS:
        return jsonify({'error': 'Unauthorized'}), 403
    
    project = db.get_project_by_id(project_id)
    if not project:
        return jsonify({'error': 'Project not found'}), 404
    
    user = db.get_user_by_id(project['user_id'])
    if user:
        project['slack_id'] = user['slack_id']
        project['nickname'] = user['nickname']
    
    data = request.get_json()
    reason = data.get('reason', '') if data else ''
    
    success = db.update_project_status(project_id, 'Building')
    
    if success:
        slack.project_rejected(project, reason)
        
    return jsonify({'success': success})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)