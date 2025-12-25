FROM python:3.9-slim

# =========================
# 🔐 Secure environment
# =========================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# =========================
# 📁 Work directory
# =========================
WORKDIR /app

# =========================
# 👤 Non-root user
# =========================
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup --home /app appuser

# =========================
# 📦 System dependencies (minimal)
# =========================
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# =========================
# 📦 Python dependencies
# =========================
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# =========================
# 📂 Application source
# =========================
COPY . .

# =========================
# 🔐 Permissions
# =========================
RUN chown -R appuser:appgroup /app

USER appuser

# =========================
# 🌐 Exposed port
# =========================
EXPOSE 5000

# =========================
# 🚀 Run application
# =========================
CMD ["python", "app.py"]
