# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Install necessary tools
RUN apt-get update && apt-get install -y gettext-base logrotate awscli && rm -rf /var/lib/apt/lists/*

# Set environment variables for AWS metadata service timeout
ENV AWS_METADATA_SERVICE_TIMEOUT=5
ENV AWS_METADATA_SERVICE_NUM_ATTEMPTS=3

# Set the working directory in the container
WORKDIR /usr/src/app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir boto3

# Copy the application code and configuration templates
COPY . .

# Copy docker and configuration templates from the 'docker' folder
COPY docker/run_logrotate.sh ./run_logrotate.sh
COPY docker/rla.yaml.template ./rla.yaml.template
COPY docker/setup.sh ./setup.sh

# Set executable permissions for the docker scripts
RUN chmod +x ./run_logrotate.sh
RUN chmod +x ./setup.sh

# Set the entry point to setup and start the application
ENTRYPOINT ["./setup.sh"]
