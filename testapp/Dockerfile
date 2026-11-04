# Deliberately vulnerable test target. Only started with `docker compose --profile test`.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN useradd --create-home --uid 10002 testapp
COPY testapp/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY testapp/app.py testapp/serve.py /app/
USER testapp
EXPOSE 8080 8443
# HTTP on 8080 and, for the Weak Cryptography weaknesses, a weak HTTPS site on 8443.
CMD ["python", "serve.py", "--host", "0.0.0.0", "--port", "8080", "--tls-port", "8443"]
