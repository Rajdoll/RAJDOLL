FROM python:3.11-slim

ARG DALFOX_VERSION=2.9.1
ARG FFUF_VERSION=2.1.0

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl ca-certificates tar sqlmap \
		libgobject-2.0-0 libpango-1.0-0 libpangocairo-1.0-0 \
		libgdk-pixbuf-2.0-0 libcairo2 libffi-dev \
	&& curl -L "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_amd64.tar.gz" -o /tmp/dalfox.tar.gz \
	&& tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin dalfox \
	&& curl -L "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz \
	&& tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
	&& chmod +x /usr/local/bin/dalfox /usr/local/bin/ffuf \
	&& rm -rf /var/lib/apt/lists/* /tmp/dalfox.tar.gz /tmp/ffuf.tar.gz

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

