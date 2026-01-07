import sqlite3
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

DB_NAME = 'users.db'

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            nickname TEXT,
            slack_id TEXT,
            ship_uuid TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            demo_link TEXT,
            github_link TEXT,
            hackatime_project TEXT,
            hours REAL DEFAULT 0,
            status TEXT DEFAULT 'Building',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status)')

def get_or_create_user(email: str, nickname: Optional[str] = None, slack_id: Optional[str] = None) -> int:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        if result:
            return result[0]
        import uuid
        ship_uuid = str(uuid.uuid4())
        c.execute(
            'INSERT INTO users (email, nickname, slack_id, ship_uuid) VALUES (?, ?, ?, ?)',
            (email, nickname, slack_id, ship_uuid)
        )
        return c.lastrowid

def get_user_by_uuid(uuid_str: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE ship_uuid = ?', (uuid_str,))
        result = c.fetchone()
        return dict(result) if result else None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        return dict(result) if result else None

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        return dict(result) if result else None

def get_user_by_slack_id(slack_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE slack_id = ?', (slack_id,))
        result = c.fetchone()
        return dict(result) if result else None

def update_user(user_id: int, nickname: Optional[str] = None, slack_id: Optional[str] = None) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        updates = []
        params = []
        if nickname is not None:
            updates.append('nickname = ?')
            params.append(nickname)
        if slack_id is not None:
            updates.append('slack_id = ?')
            params.append(slack_id)
        if not updates:
            return False
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        c.execute(query, params)
        return c.rowcount > 0

def get_all_users() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users ORDER BY created_at DESC')
        return [dict(row) for row in c.fetchall()]

def create_project(
    user_id: int,
    title: str,
    description: Optional[str] = None,
    demo_link: Optional[str] = None,
    github_link: Optional[str] = None,
    hackatime_project: Optional[str] = None,
    hours: float = 0
) -> int:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            '''INSERT INTO projects
            (user_id, title, description, demo_link, github_link, hackatime_project, hours)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (user_id, title, description, demo_link, github_link, hackatime_project, hours)
        )
        return c.lastrowid

def get_project_by_id(project_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM projects WHERE id = ?', (project_id,))
        result = c.fetchone()
        return dict(result) if result else None

def get_user_projects(user_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        if status:
            c.execute(
                '''SELECT * FROM projects
                WHERE user_id = ? AND status = ?
                ORDER BY created_at DESC''',
                (user_id, status)
            )
        else:
            c.execute(
                'SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
        return [dict(row) for row in c.fetchall()]

def update_project(
    project_id: int,
    title: Optional[str] = None,
    description: Optional[str] = None,
    demo_link: Optional[str] = None,
    github_link: Optional[str] = None,
    hackatime_project: Optional[str] = None,
    hours: Optional[float] = None,
    status: Optional[str] = None
) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        updates = []
        params = []
        if title is not None:
            updates.append('title = ?')
            params.append(title)
        if description is not None:
            updates.append('description = ?')
            params.append(description)
        if demo_link is not None:
            updates.append('demo_link = ?')
            params.append(demo_link)
        if github_link is not None:
            updates.append('github_link = ?')
            params.append(github_link)
        if hackatime_project is not None:
            updates.append('hackatime_project = ?')
            params.append(hackatime_project)
        if hours is not None:
            updates.append('hours = ?')
            params.append(hours)
        if status is not None:
            updates.append('status = ?')
            params.append(status)
        if not updates:
            return False
        params.append(project_id)
        query = f"UPDATE projects SET {', '.join(updates)} WHERE id = ?"
        c.execute(query, params)
        return c.rowcount > 0

def delete_project(project_id: int) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM projects WHERE id = ?', (project_id,))
        return c.rowcount > 0

def check_project_owner(project_id: int, user_id: int) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT user_id FROM projects WHERE id = ?', (project_id,))
        result = c.fetchone()
        return result is not None and result[0] == user_id

def update_project_status(project_id: int, status: str) -> bool:
    return update_project(project_id, status=status)

def update_project_hours(project_id: int, hours: float) -> bool:
    return update_project(project_id, hours=hours)

def add_project_hours(project_id: int, hours: float) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            'UPDATE projects SET hours = hours + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (hours, project_id)
        )
        return c.rowcount > 0

def get_all_projects(status: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        c = conn.cursor()
        if status:
            c.execute(
                '''SELECT p.*, u.nickname, u.email, u.slack_id
                FROM projects p
                JOIN users u ON p.user_id = u.id
                WHERE p.status = ?
                ORDER BY p.created_at DESC''',
                (status,)
            )
        else:
            c.execute(
                '''SELECT p.*, u.nickname, u.email, u.slack_id
                FROM projects p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.created_at DESC'''
            )
        return [dict(row) for row in c.fetchall()]

def count_projects(user_id: Optional[int] = None, status: Optional[str] = None) -> int:
    with get_db_connection() as conn:
        c = conn.cursor()
        if user_id and status:
            c.execute(
                'SELECT COUNT(*) FROM projects WHERE user_id = ? AND status = ?',
                (user_id, status)
            )
        elif user_id:
            c.execute('SELECT COUNT(*) FROM projects WHERE user_id = ?', (user_id,))
        elif status:
            c.execute('SELECT COUNT(*) FROM projects WHERE status = ?', (status,))
        else:
            c.execute('SELECT COUNT(*) FROM projects')
        return c.fetchone()[0]

def get_total_hours(user_id: Optional[int] = None) -> float:
    with get_db_connection() as conn:
        c = conn.cursor()
        if user_id:
            c.execute('SELECT COALESCE(SUM(hours), 0) FROM projects WHERE user_id = ?', (user_id,))
        else:
            c.execute('SELECT COALESCE(SUM(hours), 0) FROM projects')
        return c.fetchone()[0]

def get_project_stats() -> Dict[str, Any]:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM projects')
        total_projects = c.fetchone()[0]
        c.execute('SELECT status, COUNT(*) FROM projects GROUP BY status')
        status_counts = {row[0]: row[1] for row in c.fetchall()}
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        c.execute('SELECT COUNT(DISTINCT user_id) FROM projects')
        users_with_projects = c.fetchone()[0]
        c.execute('SELECT COALESCE(SUM(hours), 0) FROM projects')
        total_hours = c.fetchone()[0]
        return {
            'total_projects': total_projects,
            'total_users': total_users,
            'users_with_projects': users_with_projects,
            'total_hours': total_hours,
            'status_counts': status_counts
        }
