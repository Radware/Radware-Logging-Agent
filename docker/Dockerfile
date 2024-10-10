# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Install necessary tools
RUN apt-get update && apt-get install -y gettext-base logrotate && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and configuration templates
COPY . .  # Assuming all other necessary application files are in the current directory

# Copy docker and configuration templates from the 'docker' folder
COPY docker/start.sh ./start.sh
COPY docker/run_logrotate.sh ./run_logrotate.sh
COPY docker/rla.yaml.template ./rla.yaml.template

# Set executable permissions for the docker
RUN chmod +x ./start.sh
RUN chmod +x ./run_logrotate.sh

# Copy logrotate configuration
COPY docker/rla_logrotate.conf /etc/logrotate.d/rla

# Run the startup script and logrotate script concurrently
CMD ./start.sh & ./run_logrotate.sh
