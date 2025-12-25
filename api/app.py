from flask import Flask, request, jsonify, abort
import sqlite3
import os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect

app = Flask(__name__)

# =======================
# 🔐 CONFIGURATION FLASK SÉCURISÉE
# =======================
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    JSONIFY_PRETTYPRINT_REGULAR=False,
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1MB max
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True
)

csrf = CSRFProtect(app)

DATABASE = "users.db"
SAFE_FILES_DIR = Path("files").resolve()


# =======================
# 🔒 HEADERS DE SÉCURITÉ
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
@csrf.exempt  # API token-based
def login():
    if not request.is_json:
        abort(400)

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        abort(400)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

    if not row:
        abort(401)

    if check_password_hash(row[0], password):
        return jsonify({"status": "success"})

    abort(401)


# =======================
# 🧮 COMPUTE
# =======================
@app.route("/compute", methods=["POST"])
@csrf.exempt
def compute():
    if not request.is_json:
        abort(400)

    data = request.get_json()

    try:
        a = float(data["a"])
        b = float(data["b"])
    except Exception:
        abort(400)

    return jsonify({"addition": a + b, "multiplication": a * b})


# =======================
# 🔑 HASH
# =======================
@app.route("/hash", methods=["POST"])
@csrf.exempt
def hash_password():
    if not request.is_json:
        abort(400)

    password = request.json.get("password")
    if not password:
        abort(400)

    return jsonify({
        "hash": generate_password_hash(password)
    })


# =======================
# 📂 READ FILE
# =======================
@app.route("/readfile", methods=["POST"])
@csrf.exempt
def readfile():
    if not request.is_json:
        abort(400)

    filename = request.json.get("filename")
    if not filename:
        abort(400)

    requested_file = (SAFE_FILES_DIR / filename).resolve()

    if SAFE_FILES_DIR not in requested_file.parents or not requested_file.is_file():
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
