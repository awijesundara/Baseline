FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY baseline ./baseline
COPY static ./static
COPY ansible ./ansible
COPY examples ./examples
COPY COMMIT ./COMMIT
RUN useradd --create-home --shell /usr/sbin/nologin baseline \
    && mkdir -p /app/data && chown -R baseline:baseline /app
USER baseline
EXPOSE 8090
CMD ["python3", "-m", "baseline.server"]
