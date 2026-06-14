import re
from database import execute_query

# Regular expression patterns for SQL Injection signatures
SQLI_SIGNATURES = [
    (re.compile(r"'\s*or\s*.*=.*", re.IGNORECASE), 4, "Tautology/Trivial condition (e.g. ' OR 1=1)"),
    (re.compile(r"union\s+(all\s+)?select", re.IGNORECASE), 5, "Union-based injection attempt"),
    (re.compile(r";\s*(drop|delete|insert|update|create|alter|select)\b", re.IGNORECASE), 5, "Stacked query block"),
    (re.compile(r"/\*|\*/|--|#", re.IGNORECASE), 2, "SQL comment character block"),
    (re.compile(r"\b(sqlite_version|sqlite_master|sqlite_temp_master|pg_sleep|delay)\b", re.IGNORECASE), 4, "Database fingerprinting/time-delay functions"),
    (re.compile(r"\b(exec|execute|sp_executesql)\b", re.IGNORECASE), 3, "Execution block directive"),
    (re.compile(r"'\s*having\s*.*=.*", re.IGNORECASE), 4, "Having-based conditional injection"),
    (re.compile(r"\b(and|or)\s+\d+=\d+", re.IGNORECASE), 3, "Logical tautology signature"),
]

def analyze_input(input_val: str) -> dict:
    """
    Analyzes an input string against SQLi signatures.
    Returns a dictionary containing threat_score, triggered_rules, and sanitization status.
    """
    if not isinstance(input_val, str):
        return {"threat_score": 0, "triggered_rules": []}
    
    threat_score = 0
    triggered_rules = []
    
    for regex, weight, description in SQLI_SIGNATURES:
        if regex.search(input_val):
            threat_score += weight
            triggered_rules.append(description)
            
    return {
        "threat_score": threat_score,
        "triggered_rules": triggered_rules
    }

def check_payload(payload_dict: dict, username: str = "Anonymous", ip_address: str = "127.0.0.1", force_log: bool = True) -> bool:
    """
    Checks all fields in a request payload dictionary.
    Returns True if the payload is safe, False if a threat is detected.
    Optionally logs the event to the database.
    """
    max_score = 0
    all_rules = []
    suspicious_payload = ""
    
    for key, val in payload_dict.items():
        if isinstance(val, str):
            analysis = analyze_input(val)
            if analysis["threat_score"] > max_score:
                max_score = analysis["threat_score"]
                suspicious_payload = f"Field: '{key}', Value: '{val}'"
            all_rules.extend(analysis["triggered_rules"])
            
    # Threshold for blocking
    is_blocked = max_score >= 3
    
    # Log to database if threat score is positive
    if max_score > 0 and force_log:
        action_taken = "BLOCKED" if is_blocked else "PASSED"
        rules_triggered_str = ", ".join(set(all_rules))
        log_payload = f"{suspicious_payload} | Triggered: {rules_triggered_str}"
        
        execute_query(
            """
            INSERT INTO attack_logs (username, ip_address, payload, threat_score, action_taken)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, ip_address, log_payload, max_score, action_taken)
        )
        
    return not is_blocked

def sanitize_input(val: str) -> str:
    """
    Sanitizes SQL characters from a string, escaping quotes and stripping comments.
    Note: For true protection, parameterized queries must still be used.
    """
    if not isinstance(val, str):
        return val
    # Remove -- and /* comments
    cleaned = re.sub(r"--.*", "", val)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned)
    # Escape single quotes
    cleaned = cleaned.replace("'", "''")
    return cleaned
