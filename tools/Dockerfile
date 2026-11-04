# Image for the `tools` service: egress proxy + runner API + security tools.
# Build context is the repository root.

# --- Security tools, built from source at pinned versions -------------------------------------
# `go install module@version` verifies every module against the Go checksum database, so the
# binaries are reproducible from the pinned versions (TRD P7).
FROM golang:1.26.10 AS gotools
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}

# --- Runtime ----------------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    RAJDOLL_TOOL_BIN_DIR=/opt/tools/bin \
    RAJDOLL_TEMPLATE_DIR=/opt/rajdoll-templates \
    RAJDOLL_TOOL_HOME=/data/home

WORKDIR /app

RUN useradd --create-home --uid 10001 rajdoll \
    && mkdir -p /data/home \
    && chown -R rajdoll:rajdoll /data

COPY tools/requirements.txt /app/tools/requirements.txt
RUN pip install --no-cache-dir -r /app/tools/requirements.txt

COPY --from=gotools /go/bin/nuclei /go/bin/httpx /opt/tools/bin/
# Only RAJDOLL's own templates for now; pinned official nuclei templates arrive with the
# modules that use them (F5/F6).
COPY templates/nuclei /opt/rajdoll-templates

# The proxy enforces scope with the same dependency-free module the main package uses.
COPY rajdoll/__init__.py /app/rajdoll/__init__.py
COPY rajdoll/core/__init__.py /app/rajdoll/core/__init__.py
COPY rajdoll/core/scope.py /app/rajdoll/core/scope.py
COPY tools /app/tools

USER rajdoll
EXPOSE 9000 8081
CMD ["python", "-m", "tools.entrypoint"]
