# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# --- system deps -------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git build-essential default-jre \
    && rm -rf /var/lib/apt/lists/*

# --- python deps -------------------------------------------------------------
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --upgrade pip && pip install ".[local-llm]"

# --- external SAST tools (semgrep + bandit installed via pip) -----------------
RUN pip install semgrep bandit

# Gitleaks binary
ARG GITLEAKS_VERSION=8.18.4
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks

# Joern (optional; uncomment if needed in image — ~500 MB)
# ARG JOERN_VERSION=v2.0.296
# RUN curl -fsSL "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli.zip" \
#       -o /tmp/joern.zip && unzip /tmp/joern.zip -d /opt && rm /tmp/joern.zip
# ENV PATH="/opt/joern-cli:$PATH"

# --- app ---------------------------------------------------------------------
COPY . /app
RUN pip install -e .

EXPOSE 8000

ENTRYPOINT ["coba"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
