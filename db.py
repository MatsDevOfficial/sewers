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
    conn.commit()
    conn.close()

def insert_user(email, nickname, slack_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (email, nickname, slack_id) VALUES (?, ?, ?)', (email, nickname, slack_id))
    conn.commit()
    conn.close()