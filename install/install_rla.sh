#!/bin/bash

# Ensuring the script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Define application directory and service name
APP_DIR="/etc/rla"
SERVICE_NAME="rla.service"
CONFIG_FILE="$APP_DIR/rla.yaml"

# Check if the RLA installation already exists
if [ -d "$APP_DIR" ]; then
    echo "An existing RLA installation was detected in $APP_DIR."
    echo "Proceeding will overwrite the current installation."

    # Check if the rla.yaml configuration file exists
    if [ -f "$CONFIG_FILE" ]; then
        read -p "Do you want to overwrite the rla.yaml configuration file? [y/N]: " overwrite_conf
        case $overwrite_conf in
            [Yy]* )
                echo "rla.yaml will be overwritten."
                overwrite_config=true
                ;;
            * )
                echo "rla.yaml will NOT be overwritten. Please review the readme.md to ensure compatibility."
                overwrite_config=false
                ;;
        esac
    fi
else
    echo "Creating RLA directory."
    mkdir -p "$APP_DIR" || { echo "Failed to create directory $APP_DIR." ; exit 1; }
fi

# Attempt to identify the distribution
distro=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

# Function to print instructions
print_instructions() {
    echo -e "\n$1"
}

# Ensure python3-venv and pip3 are installed for Debian/Ubuntu systems
ensure_dependencies() {
    if [[ "$distro" == "ubuntu" || "$distro" == "debian" ]]; then
        echo "Ensuring python3-venv and pip3 are installed..."
        apt-get update && apt-get install -y python3-venv python3-pip || { echo "Failed to install dependencies. Exiting." ; exit 1; }
    elif [[ "$distro" == "centos" || "$distro" == "rhel" ]]; then
        echo "Ensuring python3-venv and pip3 are installed..."
        yum install -y python3-venv python3-pip || { echo "Failed to install dependencies. Exiting." ; exit 1; }
    elif [[ "$distro" == "fedora" ]]; then
        echo "Ensuring python3-venv and pip3 are installed..."
        dnf install -y python3-venv python3-pip || { echo "Failed to install dependencies. Exiting." ; exit 1; }
    else
        echo "Unsupported distribution. Please manually install python3-venv and pip3."
        exit 1
    fi
}

# Function to check Python 3.8+ installation
check_python() {
    if command -v python3 &>/dev/null; then
        python3 -c 'import sys; exit(not (sys.version_info >= (3, 8)))' || { echo "Python 3.8 or higher is required." ; exit 1; }
    else
        echo "Python 3 is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
}

# Function to check for pip3
check_pip3() {
    if ! command -v pip3 &>/dev/null; then
        print_instructions "pip3 is required but not found. Please install pip3 using your package manager."
        exit 1
    fi
}

# Main setup instructions
ensure_dependencies
check_python
check_pip3

# Create the rla user and group if they don't already exist
if ! id "rla" &>/dev/null; then
    echo "Creating rla user and group..."
    useradd -r -s /bin/false rla
    mkdir -p /home/rla
    chown rla:rla /home/rla || { echo "Failed to set ownership for /home/rla." ; exit 1; }
fi

# Set up necessary directories
echo "Creating necessary directories..."
mkdir -p /var/log/rla
chown -R rla:rla /var/log/rla || { echo "Failed to set ownership for /var/log/rla." ; exit 1; }

# Stop the service if it is running before copying files
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "Stopping the existing RLA service..."
    systemctl stop $SERVICE_NAME
fi

# Copy application files to /etc/rla/ and set correct permissions, excluding rla.yaml if necessary
echo "Copying application files to $APP_DIR..."
for file in ./*; do
    if [ "$overwrite_config" = false ] && [[ "$(basename "$file")" == "rla.yaml" ]]; then
        echo "Skipping rla.yaml as per user choice."
    else
        cp -r "$file" "$APP_DIR" || { echo "Failed to copy $file." ; exit 1; }
    fi
done
chown -R rla:rla $APP_DIR || { echo "Failed to set ownership for $APP_DIR." ; exit 1; }

# Set up Python virtual environment and install dependencies as rla user
echo "Setting up Python virtual environment and installing dependencies in $APP_DIR"
sudo -H -u rla bash -c "
cd $APP_DIR;
python3 -m venv venv; # Create virtual environment
source venv/bin/activate;
pip3 install --no-cache-dir -r requirements.txt # Install dependencies
" || { echo "Failed to set up virtual environment and install dependencies." ; exit 1; }

# Set up log rotation for /var/log/rla
echo "Setting up log rotation for /var/log/rla..."
cat > /etc/logrotate.d/rla << EOF
/var/log/rla/*.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 640 rla rla
}
EOF

# Create and enable systemd service
echo "Creating and enabling systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME << EOF
[Unit]
Description=Radware Logging Agent
After=network.target

[Service]
User=rla
Group=rla
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python3 radware_logging_agent.py

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start service
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME || { echo "Failed to start $SERVICE_NAME." ; exit 1; }

echo "Installation and service setup completed successfully."
