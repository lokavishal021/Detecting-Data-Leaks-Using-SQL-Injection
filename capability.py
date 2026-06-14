import secrets
from database import execute_query

# Permitted scopes in the system
VALID_SCOPES = {
    "vault:read": "Allows reading records in the secure vault",
    "vault:write": "Allows inserting new records to the secure vault",
    "vault:delete": "Allows removing records from the secure vault"
}

def generate_capability_code(user_id: int, scope: str) -> str:
    """
    Generates a secure, random capability token for a given user and scope.
    """
    if scope not in VALID_SCOPES:
        raise ValueError(f"Invalid scope '{scope}'. Must be one of: {list(VALID_SCOPES.keys())}")
        
    # Generate random URL-safe token
    random_part = secrets.token_urlsafe(16)
    code = f"CAP-{scope.replace(':', '-').upper()}-{random_part}"
    
    # Insert code into capability_codes table
    execute_query(
        """
        INSERT INTO capability_codes (user_id, code, scope)
        VALUES (?, ?, ?)
        """,
        (user_id, code, scope)
    )
    
    return code

def validate_capability(user_id: int, code: str, required_scope: str) -> bool:
    """
    Checks if a capability code is valid, belongs to the specified user, and grants the required scope.
    """
    if not code:
        return False
        
    # Query database to find code
    result = execute_query(
        """
        SELECT scope FROM capability_codes 
        WHERE user_id = ? AND code = ?
        """,
        (user_id, code),
        fetch_one=True
    )
    
    if not result:
        return False
        
    scope = result["scope"]
    
    # Verify scope matches required scope
    # Standard check: check direct scope match
    if scope == required_scope:
        return True
        
    # Admin/Superuser checks could be added here in future
    return False

def get_user_capabilities(user_id: int) -> list:
    """
    Retrieves all capability codes and scopes associated with a user.
    """
    results = execute_query(
        """
        SELECT id, code, scope, created_at FROM capability_codes 
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user_id,),
        fetch_all=True
    )
    
    return [dict(row) for row in results]

def revoke_capability(user_id: int, code: str) -> bool:
    """
    Deletes/revokes a capability code.
    """
    try:
        execute_query(
            """
            DELETE FROM capability_codes 
            WHERE user_id = ? AND code = ?
            """,
            (user_id, code)
        )
        return True
    except Exception:
        return False

def seed_default_capabilities(user_id: int) -> dict:
    """
    Seeds a user with a default set of standard read/write capability codes.
    """
    seeded = {}
    for scope in VALID_SCOPES:
        try:
            code = generate_capability_code(user_id, scope)
            seeded[scope] = code
        except Exception as e:
            # Code might already exist or DB error
            pass
    return seeded
