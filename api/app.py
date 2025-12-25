from flask import Flask, request, jsonify, abort
import sqlite3
import os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect

app = Flask(__name__)

# =======================
# 🔐 SECURE FLASK CONFIG
# =======================
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),  # FIX: fallback key
    JSONIFY_PRETTYPRINT_REGULAR=False,
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1MB max
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True
)

csrf = CSRFProtect(app)

DATABASE = "users.db"
SAFE_FILES_DIR = Path("files").resolve()
SAFE_FILES_DIR.mkdir(exist_ok=True)  # FIX: ensure directory exists


# =======================
# 🔒 SECURITY HEADERS
# =======================
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# =======================
# 🔐 LOGIN
# =======================
@app.route("/login", methods=["POST"])
@csrf.exempt  # token-based API
def login():
    if not request.is_json:
        abort(400, "JSON required")

    data = request.get_json(silent=True)
    if not data:
        abort(400, "Invalid JSON")

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        abort(400, "Missing credentials")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

    if row and check_password_hash(row[0], password):
        return jsonify({"status": "success"}), 200

    abort(401, "Invalid credentials")


# =======================
# 🧮 COMPUTE
# =======================
@app.route("/compute", methods=["POST"])
@csrf.exempt
def compute():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True)
    if not data:
        abort(400)

    try:
        a = float(data.get("a"))
        b = float(data.get("b"))
    except (TypeError, ValueError):
        abort(400, "Invalid numbers")

    return jsonify({
        "addition": a + b,
        "multiplication": a * b
    })


# =======================
# 🔑 HASH PASSWORD
# =======================
@app.route("/hash", methods=["POST"])
@csrf.exempt
def hash_password():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True)
    if not data or not data.get("password"):
        abort(400)

    return jsonify({
        "hash": generate_password_hash(data["password"])
    })


# =======================
# 📂 READ FILE (SECURE)
# =======================
@app.route("/readfile", methods=["POST"])
@csrf.exempt
def readfile():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True)
    filename = data.get("filename") if data else None

    if not filename:
        abort(400)

    requested_file = (SAFE_FILES_DIR / filename).resolve()

    # FIX: strong path traversal protection
    if not requested_file.is_file() or not str(requested_file).startswith(str(SAFE_FILES_DIR)):
        abort(403)

    return jsonify({
        "content": requested_file.read_text(encoding="utf-8", errors="ignore")
    })


# =======================
# 🐞 DEBUG
# =======================
@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({"debug": False})


# =======================
# 👋 HELLO
# =======================
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Secure DevSecOps API"})


# =======================
# 🚀 RUN
# =======================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
