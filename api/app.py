from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import re

app = Flask(__name__)

# ❌ Suppression du secret hardcodé
# Utilisation des variables d’environnement
SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret")
app.config["SECRET_KEY"] = SECRET_KEY


# =======================
# 🔐 Connexion sécurisée
# =======================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    # Hash sécurisé du mot de passe (SHA-256)
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ Requête préparée (anti SQL Injection)
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hashed_pwd)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =======================
# 🛡️ Ping sécurisé
# =======================
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Validation simple du hostname / IP
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        # ✅ Pas de shell=True
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
            timeout=3
        )
        return jsonify({"output": output.decode()})
    except subprocess.CalledProcessError:
        return jsonify({"error": "Ping failed"}), 500


# =======================
# 🧮 Calcul sécurisé
# =======================
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "")

    # ✅ Autoriser uniquement des opérations simples
    if not re.match(r"^[0-9+\-*/(). ]+$", expression):
        return jsonify({"error": "Invalid expression"}), 400

    try:
        result = eval(expression, {"__builtins__": {}})
        return jsonify({"result": result})
    except Exception:
        return jsonify({"error": "Computation error"}), 400


# =======================
# 🔑 Hash sécurisé
# =======================
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "")

    # ✅ SHA-256 au lieu de MD5
    hashed = hashlib.sha256(pwd.encode()).hexdigest()
    return jsonify({"sha256": hashed})


# =======================
# 📂 Lecture de fichier sécurisée
# =======================
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")

    # Répertoire autorisé
    BASE_DIR = os.path.abspath("files")
    file_path = os.path.abspath(os.path.join(BASE_DIR, filename))

    # ✅ Protection contre Path Traversal
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    with open(file_path, "r") as f:
        content = f.read()

    return jsonify({"content": content})


# =======================
# 🐞 Debug sécurisé
# =======================
@app.route("/debug", methods=["GET"])
def debug():
    # ❌ Plus aucune fuite sensible
    return jsonify({"debug": False})


# =======================
# 👋 Hello
# =======================
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secure DevSecOps API"})


if __name__ == "__main__":
    # ❌ debug=False en production
    app.run(host="0.0.0.0", port=5000, debug=False)
