
from flask import Flask, request, escape
import subprocess
import os
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup

app = Flask(__name__)

# Load secrets from environment (never hardcode)
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'secure_default_change_me'))
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    if username == "admin" and check_password_hash(ADMIN_PASSWORD_HASH, password or ''):
        return "Logged in successfully"
    return "Invalid credentials", 401

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Whitelist to prevent injection
    allowed_hosts = ['localhost', '127.0.0.1', 'google.com', '8.8.8.8']
    if host not in allowed_hosts:
        return "Invalid host", 400
    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout
        return "Ping failed", 500
    except subprocess.TimeoutExpired:
        return "Ping timeout", 408
    except Exception:
        return "Ping error", 500

@app.route("/hello")
def hello():
    name = request.args.get("name", "user")
    # Auto-escape to prevent XSS
    safe_name = escape(name)
    return Markup(f"<h1>Hello {safe_name}!</h1>")

if __name__ == "__main__":
    # NEVER use debug=True in production
    app.run(debug=False, host='127.0.0.1', port=5000)
