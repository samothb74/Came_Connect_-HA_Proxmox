ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM ${BUILD_FROM}

WORKDIR /app

COPY requirements.txt .
RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir -r requirements.txt

COPY . /app
RUN chmod a+x /app/run.sh

CMD [ "/app/run.sh" ]