import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        nickname TEXT,
        slack_id TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        description TEXT,
        demo_link TEXT,
        github_link TEXT,
        hackatime_project TEXT,
        status TEXT DEFAULT 'Building',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.commit()
    conn.close()

def insert_user(email, nickname, slack_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (email, nickname, slack_id) VALUES (?, ?, ?)', (email, nickname, slack_id))
    if c.lastrowid == 0:
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user_id = c.fetchone()[0]
    else:
        user_id = c.lastrowid
    conn.commit()
    conn.close()
    return user_id

def insert_project(user_id, title, description, demo_link, github_link, hackatime_project):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO projects (user_id, title, description, demo_link, github_link, hackatime_project) VALUES (?, ?, ?, ?, ?, ?)', (user_id, title, description, demo_link, github_link, hackatime_project))
    conn.commit()
    conn.close()

def get_projects(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, title, description, demo_link, github_link, hackatime_project, status, created_at FROM projects WHERE user_id = ?', (user_id,))
    projects = c.fetchall()
    conn.close()
    return projects

def update_project(project_id, title, description, demo_link, github_link, hackatime_project):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE projects SET title=?, description=?, demo_link=?, github_link=?, hackatime_project=? WHERE id=?', (title, description, demo_link, github_link, hackatime_project, project_id))
    conn.commit()
    conn.close()
    
def check_project_owner(project_id, user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT user_id FROM projects WHERE id = ?', (project_id,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == user_id

def delete_project(project_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM projects WHERE id = ?', (project_id,))
    conn.commit()
    conn.close()

def count_all_projects():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM projects')
    count = c.fetchone()[0]
    conn.close()
    return count

def get_all_projects():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        SELECT p.id, p.title, p.description, p.demo_link, p.github_link, p.hackatime_project, p.status, p.created_at, u.nickname, u.slack_id
        FROM projects p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ''')
    projects = c.fetchall()
    conn.close()
    return projects