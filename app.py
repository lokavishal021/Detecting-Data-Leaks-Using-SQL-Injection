import os
import bcrypt
import sqlite3
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import database
from database import init_db, execute_query, execute_unsafe_query
import security
import encryption
import capability

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_session_key_2026_antigravity")

# Initialize database tables on app startup
with app.app_context():
    init_db()

# Helper to verify session and get user ID
def get_logged_in_user():
    if "user_id" in session:
        return session["user_id"], session["username"]
    return None, None

@app.route("/")
def index():
    """Serves the main SPA interface."""
    return render_template("index.html")

# --- AUTH ENPOINTS ---

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
        
    # Standard security check for input sanitation / SQLi detection on username (Layer 1)
    if not security.check_payload({"username": username, "password": password}, username="Registration", ip_address=request.remote_addr):
        return jsonify({"error": "Request blocked by Layer 1 Security WAF: Malicious payload detected."}), 400
        
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    try:
        user_id = execute_query(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        # Seed user with default capability codes for academic demo
        capability.seed_default_capabilities(user_id)
        
        return jsonify({"message": "Registration successful. You can now log in.", "user_id": user_id})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
        
    # Layer 1 scan
    if not security.check_payload({"username": username, "password": password}, username="Login Attempt", ip_address=request.remote_addr):
        return jsonify({"error": "Request blocked by Layer 1 Security WAF: Malicious payload detected."}), 400
        
    user = execute_query(
        "SELECT * FROM users WHERE username = ?",
        (username,),
        fetch_one=True
    )
    
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "username": user["username"]})
    
    # Log a failed attempt with moderate alert if they seem to be querying SQL but it didn't trip the regex
    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/api/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route("/api/profile", methods=["GET"])
def profile():
    user_id, username = get_logged_in_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user_id": user_id, "username": username})


# --- SECURE VAULT ENDPOINTS ---

@app.route("/api/vault", methods=["GET", "POST", "DELETE"])
def vault():
    user_id, username = get_logged_in_user()
    if not user_id:
        return jsonify({"error": "Unauthorized. Please log in first."}), 401
        
    # Get configuration header or params to decide if Layer 1 is active (default True)
    waf_enabled = request.headers.get("X-Enable-WAF", "true").lower() == "true"
    
    # Layer 1 filter
    if waf_enabled:
        # Scan parameters and request body
        payload_to_check = {}
        if request.method == "GET":
            payload_to_check.update(request.args.to_dict())
        else:
            payload_to_check.update(request.json or {})
            
        if not security.check_payload(payload_to_check, username=username, ip_address=request.remote_addr):
            return jsonify({"error": "Request blocked by Layer 1 Security WAF: Potential SQL Injection attack detected."}), 403

    # Layer 2 check: Capability validation
    capability_check = request.headers.get("X-Enable-Capability", "true").lower() == "true"
    
    if request.method == "GET":
        cap_code = request.args.get("capability_code")
        if capability_check and not capability.validate_capability(user_id, cap_code, "vault:read"):
            return jsonify({"error": "Layer 2 Error: Invalid or missing Capability Code for 'vault:read'."}), 403
            
        search_query = request.args.get("search", "")
        # Normal, secure parameterized query
        if search_query:
            query = "SELECT * FROM vault_data WHERE user_id = ? AND (title LIKE ? OR encrypted_content LIKE ?)"
            params = (user_id, f"%{search_query}%", f"%{search_query}%")
        else:
            query = "SELECT * FROM vault_data WHERE user_id = ?"
            params = (user_id,)
            
        rows = execute_query(query, params, fetch_all=True)
        
        # AES-256 Decryption Layer
        user_key = encryption.get_encryption_key(username)
        data_list = []
        for row in rows:
            decrypted = encryption.decrypt_data(row["encrypted_content"], user_key)
            data_list.append({
                "id": row["id"],
                "title": row["title"],
                "content": decrypted,
                "encrypted_raw": row["encrypted_content"]
            })
        return jsonify(data_list)
        
    elif request.method == "POST":
        data = request.json or {}
        cap_code = data.get("capability_code")
        
        if capability_check and not capability.validate_capability(user_id, cap_code, "vault:write"):
            return jsonify({"error": "Layer 2 Error: Invalid or missing Capability Code for 'vault:write'."}), 403
            
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()
        
        if not title or not content:
            return jsonify({"error": "Title and Content are required"}), 400
            
        # AES-256 Encryption Layer
        user_key = encryption.get_encryption_key(username)
        ciphertext = encryption.encrypt_data(content, user_key)
        
        try:
            item_id = execute_query(
                "INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, ?, ?)",
                (user_id, title, ciphertext)
            )
            return jsonify({"message": "Data saved securely in vault", "id": item_id})
        except Exception as e:
            return jsonify({"error": f"Failed to save data: {str(e)}"}), 500
            
    elif request.method == "DELETE":
        data = request.json or {}
        cap_code = data.get("capability_code")
        item_id = data.get("item_id")
        
        if capability_check and not capability.validate_capability(user_id, cap_code, "vault:delete"):
            return jsonify({"error": "Layer 2 Error: Invalid or missing Capability Code for 'vault:delete'."}), 403
            
        if not item_id:
            return jsonify({"error": "Item ID is required"}), 400
            
        try:
            execute_query("DELETE FROM vault_data WHERE user_id = ? AND id = ?", (user_id, item_id))
            return jsonify({"message": "Item deleted successfully"})
        except Exception as e:
            return jsonify({"error": f"Failed to delete item: {str(e)}"}), 500


# --- CAPABILITIES ENDPOINTS ---

@app.route("/api/capabilities", methods=["GET", "POST", "DELETE"])
def capabilities():
    user_id, username = get_logged_in_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    if request.method == "GET":
        caps = capability.get_user_capabilities(user_id)
        return jsonify(caps)
        
    elif request.method == "POST":
        data = request.json or {}
        scope = data.get("scope")
        try:
            code = capability.generate_capability_code(user_id, scope)
            return jsonify({"message": "Capability code generated", "code": code, "scope": scope})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
            
    elif request.method == "DELETE":
        data = request.json or {}
        code = data.get("code")
        if capability.revoke_capability(user_id, code):
            return jsonify({"message": "Capability revoked successfully"})
        return jsonify({"error": "Failed to revoke capability"}), 400


# --- SOC ATTACK LOGS ENDPOINTS ---

@app.route("/api/logs", methods=["GET", "DELETE"])
def attack_logs():
    if request.method == "GET":
        logs = execute_query(
            "SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 50",
            fetch_all=True
        )
        return jsonify([dict(row) for row in logs])
    elif request.method == "DELETE":
        execute_query("DELETE FROM attack_logs")
        return jsonify({"message": "Security logs cleared."})


# --- SECURITY SIMULATOR (CORE ACADEMIC ENGINE) ---

@app.route("/api/simulate", methods=["POST"])
def simulate_attack():
    """
    Simulates database searching under configured security layers:
    - Layer 1 WAF toggle
    - Layer 2 Parameterized Queries toggle
    - Layer 2 Decryption toggle
    - Layer 2 Capability Check toggle
    """
    user_id, username = get_logged_in_user()
    
    # If not logged in, map to a default simulator sandbox user
    if not user_id:
        # Auto-create/find sandbox user
        sandbox_user = execute_query("SELECT id FROM users WHERE username = 'sandbox_user'", fetch_one=True)
        if not sandbox_user:
            # Create sandbox user and seed items
            pw_hash = bcrypt.hashpw(b"sandbox_password", bcrypt.gensalt()).decode("utf-8")
            try:
                sandbox_id = execute_query("INSERT INTO users (username, password_hash) VALUES ('sandbox_user', ?)", (pw_hash,))
                capability.seed_default_capabilities(sandbox_id)
                # Seed test data for demonstration
                key = encryption.get_encryption_key("sandbox_user")
                execute_query("INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, 'SSN Records', ?)", (sandbox_id, encryption.encrypt_data("123-456-7890 (Top Secret SSN)", key)))
                execute_query("INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, 'Financial Ledger', ?)", (sandbox_id, encryption.encrypt_data("Revenue: $2.4M, Loss: $400K", key)))
                execute_query("INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, 'Academic Grades', ?)", (sandbox_id, encryption.encrypt_data("Math: A+, Coding: A+", key)))
                user_id = sandbox_id
                username = "sandbox_user"
            except Exception:
                # In case of concurrent request or DB lock
                sandbox_user = execute_query("SELECT id FROM users WHERE username = 'sandbox_user'", fetch_one=True)
                user_id = sandbox_user["id"]
                username = "sandbox_user"
        else:
            user_id = sandbox_user["id"]
            username = "sandbox_user"

    data = request.json or {}
    payload = data.get("payload", "").strip()
    waf_enabled = data.get("waf_enabled", True)
    parameterized_enabled = data.get("parameterized_enabled", True)
    decryption_enabled = data.get("decryption_enabled", True)
    capability_check_enabled = data.get("capability_check_enabled", True)
    cap_code = data.get("capability_code", "").strip()
    
    ip_address = request.remote_addr
    
    # Live analyzer info for threat display
    analysis = security.analyze_input(payload)
    threat_score = analysis["threat_score"]
    
    # 1. LAYER 1: SQL Injection WAF Protection
    if waf_enabled:
        is_safe = security.check_payload({"payload": payload}, username=username, ip_address=ip_address)
        if not is_safe:
            return jsonify({
                "status": "BLOCKED",
                "message": "Block Reason: SQL Injection payload detected by Layer 1 Security WAF.",
                "threat_score": threat_score,
                "rules_triggered": analysis["triggered_rules"],
                "query_executed": "None (Execution aborted)",
                "results": []
            }), 200 # Return 200 so simulator client renders it cleanly
            
    # If WAF passed or was disabled, but payload is still malicious, log it as PASSED
    if not waf_enabled and threat_score > 0:
        rules_triggered_str = ", ".join(analysis["triggered_rules"])
        execute_query(
            "INSERT INTO attack_logs (username, ip_address, payload, threat_score, action_taken) VALUES (?, ?, ?, ?, ?)",
            (username, ip_address, f"Simulator Bypass | '{payload}' | Triggered: {rules_triggered_str}", threat_score, "PASSED")
        )

    # 2. LAYER 2: Capability authorization
    if capability_check_enabled:
        if not capability.validate_capability(user_id, cap_code, "vault:read"):
            # Log capability failure
            execute_query(
                "INSERT INTO attack_logs (username, ip_address, payload, threat_score, action_taken) VALUES (?, ?, ?, ?, ?)",
                (username, ip_address, f"Capability Fail | Token: {cap_code}", 3, "BLOCKED (CAPABILITY)")
            )
            return jsonify({
                "status": "UNAUTHORIZED",
                "message": "Access Denied: Invalid or unauthorized Capability Code.",
                "threat_score": threat_score,
                "rules_triggered": ["Capability Authorization Failure"],
                "query_executed": "None (Access Denied)",
                "results": []
            }), 200

    # 3. Execution pathway (Parameterized vs Unsafe)
    query_executed = ""
    results = []
    error_message = ""
    
    user_key = encryption.get_encryption_key(username)
    
    try:
        if parameterized_enabled:
            query_executed = f"SELECT * FROM vault_data WHERE user_id = ? AND (title LIKE ? OR encrypted_content LIKE ?);"
            # Standard safe binding
            param_str = f"%{payload}%"
            rows = execute_query(
                "SELECT * FROM vault_data WHERE user_id = ? AND (title LIKE ? OR encrypted_content LIKE ?)",
                (user_id, param_str, param_str),
                fetch_all=True
            )
            
            for row in rows:
                content_val = row["encrypted_content"]
                if decryption_enabled:
                    content_val = encryption.decrypt_data(content_val, user_key)
                results.append({
                    "id": row["id"],
                    "title": row["title"],
                    "encrypted_content": content_val,
                    "is_decrypted": decryption_enabled
                })
        else:
            # UNSAFE SQL dynamic execution
            # Vulnerable to SQL Injection!
            query_executed = f"SELECT * FROM vault_data WHERE user_id = {user_id} AND (title LIKE '%{payload}%' OR encrypted_content LIKE '%{payload}%');"
            
            # Since executing raw query can return rows, we run custom raw execute
            conn = sqlite3.connect(database.DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            try:
                # We execute raw string concatenation
                cursor.execute(query_executed)
                rows = cursor.fetchall()
                conn.commit()
                
                for row in rows:
                    # Depending on SQLi UNION payloads, returned row might not have user_id, title, or encrypted_content
                    # So we dynamically serialize whatever columns SQLite returns
                    row_dict = {}
                    for idx, col in enumerate(cursor.description):
                        col_name = col[0]
                        val = row[idx]
                        
                        # Apply decryption strictly to 'encrypted_content' column if GCM decrypt is requested
                        if col_name == 'encrypted_content':
                            if decryption_enabled:
                                val = encryption.decrypt_data(val, user_key)
                            row_dict["is_decrypted"] = decryption_enabled
                        
                        row_dict[col_name] = val
                    results.append(row_dict)
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
                
    except Exception as e:
        error_message = str(e)
        return jsonify({
            "status": "SQL_ERROR",
            "message": f"Database SQL Error: {error_message}",
            "threat_score": threat_score,
            "rules_triggered": analysis["triggered_rules"],
            "query_executed": query_executed,
            "results": []
        }), 200
        
    return jsonify({
        "status": "SUCCESS",
        "message": "Query executed successfully.",
        "threat_score": threat_score,
        "rules_triggered": analysis["triggered_rules"],
        "query_executed": query_executed,
        "results": results
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
