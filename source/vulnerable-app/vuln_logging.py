# Intentionally vulnerable: missing security logging → A09 (partial)

def login(username, password):
    # Authentication attempt with NO logging of failures
    if check_credentials(username, password):
        return {"status": "ok", "token": generate_token(username)}
    # No logging of failed login attempt
    return {"status": "error", "message": "Invalid credentials"}

def admin_action(user, action):
    # Privileged action with no audit trail
    if not user.get("is_admin"):
        # No logging of unauthorized access attempt
        return {"error": "forbidden"}
    perform_action(action)
    return {"status": "done"}

def check_credentials(username, password):
    pass

def generate_token(username):
    pass

def perform_action(action):
    pass
