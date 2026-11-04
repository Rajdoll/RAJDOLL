# Image for the `tools` service. Build context is the repository root.
# F0: runner skeleton only. Security tools, pinned versions, and the egress proxy arrive in F3.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 rajdoll

COPY tools/requirements.txt /app/tools/requirements.txt
RUN pip install --no-cache-dir -r /app/tools/requirements.txt

COPY tools /app/tools

USER rajdoll
EXPOSE 9000
CMD ["uvicorn", "tools.runner.app:app", "--host", "0.0.0.0", "--port", "9000"]
