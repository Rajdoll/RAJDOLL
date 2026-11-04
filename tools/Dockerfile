# Image for the `tools` service: egress proxy + runner API + security tools.
# Build context is the repository root.

# --- Security tools, built from source at pinned versions -------------------------------------
# `go install module@version` verifies every module against the Go checksum database, so the
# binaries are reproducible from the pinned versions (TRD P7).
FROM golang:1.26.10 AS gotools
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.2.1
RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
    && go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@${FFUF_VERSION}

# --- Runtime ----------------------------------------------------------------------------------
# The Debian release is named so the pinned nmap package below stays resolvable.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    RAJDOLL_TOOL_BIN_DIR=/opt/tools/bin \
    RAJDOLL_TEMPLATE_DIR=/opt/rajdoll-templates \
    RAJDOLL_WORDLIST_DIR=/opt/rajdoll-wordlists \
    RAJDOLL_TOOL_HOME=/data/home \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

WORKDIR /app

RUN useradd --create-home --uid 10001 rajdoll \
    && mkdir -p /data/home \
    && chown -R rajdoll:rajdoll /data

# nmap from Debian at a pinned version (non-HTTP tool, runs without the proxy; TRD 4.2).
# On a version mismatch the build prints what the release offers.
ARG NMAP_VERSION=7.95+dfsg-3
RUN apt-get update \
    && (apt-get install -y --no-install-recommends nmap=${NMAP_VERSION} \
        || (apt-cache policy nmap && exit 1)) \
    && rm -rf /var/lib/apt/lists/*

COPY tools/requirements.txt /app/tools/requirements.txt
RUN pip install --no-cache-dir -r /app/tools/requirements.txt
# Chromium headless shell matching the pinned Playwright release (browser adapter).
RUN python -m playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /go/bin/nuclei /go/bin/httpx /go/bin/katana /go/bin/ffuf /opt/tools/bin/
RUN ln -s /usr/bin/nmap /opt/tools/bin/nmap
COPY tools/wordlists /opt/rajdoll-wordlists
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
