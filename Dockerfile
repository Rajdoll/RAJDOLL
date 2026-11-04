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

USER rajdoll
EXPOSE 8000
CMD ["uvicorn", "rajdoll.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
