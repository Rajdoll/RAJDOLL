# Image for the `api` and `worker` services.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 rajdoll \
    && mkdir -p /secrets \
    && chown rajdoll:rajdoll /secrets

COPY pyproject.toml README.md ./
COPY rajdoll ./rajdoll
RUN pip install --no-cache-dir .
COPY alembic.ini ./
COPY migrations ./migrations

USER rajdoll
EXPOSE 8000
# Apply migrations and prepare keys, then start the web server (TRD 12, BSD 7).
CMD ["sh", "-c", "python -m rajdoll.core.bootstrap && exec uvicorn rajdoll.api.app:app --host 0.0.0.0 --port 8000"]
