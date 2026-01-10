from flask import Flask, request, jsonify, abort
import sqlite3
import os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# =======================
# 🚀 APP INIT
# =======================
app = Flask(__name__)

# =======================
# 🔐 SECURE CONFIG
# =======================
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32),
    JSONIFY_PRETTYPRINT_REGULAR=False,
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1 MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True,
)

csrf = CSRFProtect(app)

# =======================
# ⏱️ RATE LIMITING (ANTI-BRUTE-FORCE)
# =======================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# =======================
# 📦 STORAGE
# =======================
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "users.db"

SAFE_FILES_DIR = (BASE_DIR / "files").resolve()
SAFE_FILES_DIR.mkdir(exist_ok=True)

# =======================
# 🛡️ SECURITY HEADERS
# =======================
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# =======================
# 👋 HOME
# =======================
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "running", "message": "Secure DevSecOps API"})

# =======================
# 🔐 LOGIN
# =======================
@app.route("/login", methods=["POST"])
@csrf.exempt
@limiter.limit("5 per minute")
def login():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if len(username) < 3 or len(password) < 8:
        abort(400)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()

    if row and check_password_hash(row[0], password):
        return jsonify({"status": "success"}), 200

    abort(401)

# =======================
# 🧮 COMPUTE
# =======================
@app.route("/compute", methods=["POST"])
@csrf.exempt
def compute():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True) or {}

    try:
        a = float(data["a"])
        b = float(data["b"])
    except (KeyError, ValueError, TypeError):
        abort(400)

    if abs(a) > 1e6 or abs(b) > 1e6:
        abort(400)

    return jsonify({"addition": a + b, "multiplication": a * b})

# =======================
# 🔑 HASH PASSWORD
# =======================
@app.route("/hash", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute")
def hash_password():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True) or {}
    password = data.get("password")

    if not password or len(password) < 8:
        abort(400)

    return jsonify({"hash": generate_password_hash(password)})

# =======================
# 📂 READ FILE (HARDENED)
# =======================
@app.route("/readfile", methods=["POST"])
@csrf.exempt
def readfile():
    if not request.is_json:
        abort(400)

    data = request.get_json(silent=True) or {}
    filename = data.get("filename")

    if not filename or "/" in filename or "\\" in filename:
        abort(400)

    requested_file = (SAFE_FILES_DIR / filename).resolve()

    if not requested_file.is_file():
        abort(404)

    if SAFE_FILES_DIR not in requested_file.parents:
        abort(403)

    return jsonify({
        "content": requested_file.read_text(encoding="utf-8", errors="ignore")
    })

# =======================
# 🐞 DEBUG STATUS
# =======================
@app.route("/debug", methods=["GET"])
def debug_status():
    return jsonify({"debug": False})

# =======================
# 🚀 RUN
# =======================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
