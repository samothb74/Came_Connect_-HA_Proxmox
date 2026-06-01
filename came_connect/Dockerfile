ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM ${BUILD_FROM}

WORKDIR /app

RUN apk add --no-cache python3 py3-pip

COPY requirements.txt .
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN chmod a+x /app/run.sh

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app"

CMD ["/app/run.sh"]
