#!/bin/bash

echo "Radware Logging Agent Setup Instructions"
echo "----------------------------------------"

# Function to print instructions
print_instructions() {
    echo -e "\n$1"
}

# Check the Python Installation
check_python() {
    if ! command -v python3 &>/dev/null || [ "$(python3 -c 'import sys; print(sys.version_info >= (3, 8))')" != "True" ]; then
        print_instructions "Python 3.8 or higher is required but not found. Please install or update Python."
        exit 1
    fi
}

# Check for pip3
check_pip3() {
    if ! command -v pip3 &>/dev/null; then
        print_instructions "pip3 is required but not found. Please install pip3 using your package manager."
        exit 1
    fi
}

# Instructions for installing Python requirements
install_requirements_instructions() {
    print_instructions "To install the required Python packages, run the following command from the root folder of RLA:\n\n  pip3 install -r requirements.txt"
}

# Instructions for setting up the systemd service
setup_systemd_service_instructions() {
    PYTHON_PATH=$(which python3)
    SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

    cat > rla.service << EOF
[Unit]
Description=Radware Logging Agent
After=network.target

[Service]
ExecStart=$PYTHON_PATH $SCRIPT_DIR/radware_logging_agent.py
WorkingDirectory=$SCRIPT_DIR
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    print_instructions "A systemd service file has been created (rla.service). To install and enable the service, run the following commands:\n\n  sudo mv rla.service /etc/systemd/system/\n  sudo systemctl daemon-reload\n  sudo systemctl enable rla.service"
}

# Final step instructions
final_step_instructions() {
    print_instructions "Before starting the Radware Logging Agent service, please ensure you have configured your settings in rla.yaml.\n\nTo verify your configuration, you can use the following command:\n\n  python3 radware_logging_agent.py --verify\n\nIf the verification is successful, you can start the service with:\n\n  sudo systemctl start rla.service"
}

# Main setup instructions
check_python
check_pip3
install_requirements_instructions
setup_systemd_service_instructions
final_step_instructions

echo "Please follow the instructions above to complete the setup of Radware Logging Agent."
