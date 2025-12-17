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