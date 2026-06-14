import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_vault.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Vault Data Table (contains encrypted data)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)
    
    # 3. Capability Codes Table (capability-based access control tokens)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS capability_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT UNIQUE NOT NULL,
        scope TEXT NOT NULL, -- e.g., 'vault:read', 'vault:write', 'vault:delete'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)
    
    # 4. Attack Logs Table (Layer 1 WAF and general SQLi detection alerts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        payload TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        action_taken TEXT NOT NULL, -- 'BLOCKED' or 'PASSED'
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()

# Helper wrappers for database operations

def execute_query(query, params=(), fetch_all=False, fetch_one=False):
    """
    Executes a secure query using parameterized inputs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    result = None
    try:
        cursor.execute(query, params)
        if fetch_all:
            result = cursor.fetchall()
        elif fetch_one:
            result = cursor.fetchone()
        else:
            conn.commit()
            result = cursor.lastrowid
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
    return result

def execute_unsafe_query(query):
    """
    Executes an UNSAFE query (strictly for simulation of vulnerabilities).
    This runs raw SQLite execution without bindings.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    result = None
    try:
        # Executes multiple statements if user inputs a semicolon injection
        cursor.executescript(query)
        # However, executescript doesn't fetch rows, so if we want to show data leakage:
        # We can fall back to executescript or execute. Let's do raw execute.
        # In case the user inputs something that returns rows, we will try to fetch them.
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            conn.commit()
        except sqlite3.OperationalError as e:
            # Semicolon separated multiple statements raise OperationalError in standard execute.
            # So if it fails, we try executescript just in case they are trying stacking queries.
            conn.rollback()
            # Try executescript
            conn.executescript(query)
            conn.commit()
            result = []
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
    return result
