FROM python:3.9-slim

WORKDIR /app
COPY api/ .

# Mise à jour des paquets système et installation de Flask
RUN apt-get update && apt-get upgrade -y \
    && pip install --no-cache-dir flask \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 5000
CMD ["python", "app.py"]

