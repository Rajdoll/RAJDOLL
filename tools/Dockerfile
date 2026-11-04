# Image for the `tools` service: egress proxy + runner API. Build context is the repository root.
# Security tools with pinned versions are added in F3b.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN useradd --create-home --uid 10001 rajdoll \
    && mkdir -p /data \
    && chown rajdoll:rajdoll /data

COPY tools/requirements.txt /app/tools/requirements.txt
RUN pip install --no-cache-dir -r /app/tools/requirements.txt

# The proxy enforces scope with the same dependency-free module the main package uses.
COPY rajdoll/__init__.py /app/rajdoll/__init__.py
COPY rajdoll/core/__init__.py /app/rajdoll/core/__init__.py
COPY rajdoll/core/scope.py /app/rajdoll/core/scope.py
COPY tools /app/tools

USER rajdoll
EXPOSE 9000 8081
CMD ["python", "-m", "tools.entrypoint"]
