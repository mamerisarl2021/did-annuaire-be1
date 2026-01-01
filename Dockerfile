ARG PYTHON_VERSION=3.13-slim-bookworm


FROM python:${PYTHON_VERSION} AS builder

ENV UV_HTTP_TIMEOUT=300
ENV UV_HTTP_RETRIES=5
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1



RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
ENV VIRTUAL_ENV=/opt/venv

WORKDIR /app

COPY pyproject.toml uv.lock ./

# Install dependencies with layer caching
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev



FROM python:${PYTHON_VERSION} AS runner

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*


RUN useradd -m -r appuser && \
    mkdir -p /app  && \
    chown -R appuser:appuser /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV VIRTUAL_ENV=/opt/venv

WORKDIR /app

COPY --from=builder /app .
COPY --chown=appuser:appuser src /app/src
COPY --chown=appuser:appuser config /app/config
COPY --chown=appuser:appuser gunicorn.conf.py .
COPY --chown=appuser:appuser entrypoint.sh .
COPY --chown=appuser:appuser manage.py .
RUN chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 8899

CMD ["/app/entrypoint.sh"]