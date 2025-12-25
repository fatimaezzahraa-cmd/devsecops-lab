from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from pathlib import Path

app = Flask(__name__)

# =======================
# 🔐 Configuration
# =======================
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))

DATABASE = "users.db"
SAFE_FILES_DIR = Path("files").resolve()


# =======================
# 🔐 LOGIN (SQL sécurisé)
# =======================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"static_salt",  # en vrai → salt stocké par utilisateur
        100_000
    ).hex()

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = ? AND password = ?",
            (username, hashed)
        )
        user = cursor.fetchone()

    if user:
        return jsonify({"status": "success"})

    return jsonify({"status": "error"}), 401


# =======================
# 🧮 CALCUL SÉCURISÉ (sans eval)
# =======================
@app.route("/compute", methods=["POST"])
def compute():
    data = request.get_json(silent=True)
    if not data or "a" not in data or "b" not in data:
        return jsonify({"error": "Invalid input"}), 400

    try:
        a = float(data["a"])
        b = float(data["b"])
    except ValueError:
        return jsonify({"error": "Numbers only"}), 400

    return jsonify({
        "addition": a + b,
        "multiplication": a * b
    })


# =======================
# 🔑 HASH SÉCURISÉ
# =======================
@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json(silent=True)
    password = data.get("password", "")

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"static_salt",
        100_000
    ).hex()

    return jsonify({"hash": hashed})


# =======================
# 📂 LECTURE DE FICHIER SÉCURISÉE
# =======================
@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.get_json(silent=True)
    filename = data.get("filename")

    if not filename:
        return jsonify({"error": "Missing filename"}), 400

    requested_file = (SAFE_FILES_DIR / filename).resolve()

    # 🔐 Protection Path Traversal
    if not str(requested_file).startswith(str(SAFE_FILES_DIR)):
        return jsonify({"error": "Access denied"}), 403

    if not requested_file.exists():
        return jsonify({"error": "File not found"}), 404

    return jsonify({"content": requested_file.read_text()})


# =======================
# 🐞 DEBUG (désactivé)
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
    app.run(host="0.0.0.0", port=5000, debug=False)
