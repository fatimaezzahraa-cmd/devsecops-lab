FROM python:3.9-slim

# =========================
# 🔐 Variables sécurisées
# =========================
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# =========================
# 📁 Dossier de travail
# =========================
WORKDIR /app

# =========================
# 👤 User non-root
# =========================
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser

# =========================
# 📦 Dépendances
# =========================
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# =========================
# 📂 Code source
# =========================
COPY . .

RUN chown -R appuser:appgroup /app

USER appuser

# =========================
# 🌐 Port
# =========================
EXPOSE 5000

# =========================
# 🚀 Run
# =========================
CMD ["python", "app.py"]
