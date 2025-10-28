# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Basic envs and sane defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_METADATA_SERVICE_TIMEOUT=5 \
    AWS_METADATA_SERVICE_NUM_ATTEMPTS=3 \
    PYTHONPATH=/usr/src/app/src

# Install necessary tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext-base \
    logrotate \
    awscli \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir boto3

# Copy the application code
COPY . .

# Ensure the config path works: code expects src/rla.yaml,
# while setup.sh writes rla.yaml at the repo root. Create a forward symlink.
RUN mkdir -p src && ln -sf ../rla.yaml src/rla.yaml

# Place docker helper scripts/templates at repo root (ENTRYPOINT expects ./setup.sh)
RUN cp docker/run_logrotate.sh ./run_logrotate.sh \
 && cp docker/rla.yaml.template ./rla.yaml.template \
 && cp docker/setup.sh ./setup.sh \
 && chmod +x ./run_logrotate.sh ./setup.sh

# Start the app via setup script
ENTRYPOINT ["./setup.sh"]
