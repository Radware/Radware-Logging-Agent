#!/bin/bash

# Check the Linux Distribution
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)

# Function to check Python version and provide installation/update instructions
check_python() {
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
        if [[ $PY_VER < "3.8" ]]; then
            echo "Python 3.8 or higher is required. Installed version is $PY_VER."
            echo "Run the following command to update Python:"
            if [[ $distro == *"Ubuntu"* ]]; then
                echo "sudo apt-get update && sudo apt-get install python3.8"
            elif [[ $distro == *"CentOS"* ]]; then
                echo "sudo yum update && sudo yum install python3.8"
            fi
            exit 1
        fi
    else
        echo "Python 3 is not installed. Run the following command to install Python 3.8:"
        if [[ $distro == *"Ubuntu"* ]]; then
            echo "sudo apt-get update && sudo apt-get install python3.8"
        elif [[ $distro == *"CentOS"* ]]; then
            echo "sudo yum update && sudo yum install python3.8"
        fi
        exit 1
    fi
}


# Function to check for pip3
check_pip3() {
    if ! command -v pip3 &>/dev/null; then
        echo "pip3 is not installed. Run the following command to install it:"
        if [[ $distro == *"Ubuntu"* ]]; then
            echo "sudo apt-get install python3-pip"
        elif [[ $distro == *"CentOS"* ]]; then
            echo "sudo yum install python3-pip"
        fi
    else
        echo "pip3 is installed."
    fi
}


# Function to provide command for installing Python requirements
install_requirements_cmd() {
    echo "Run the following command to install the required Python packages:"
    echo "pip3 install -r requirements.txt"
}

# Function to output directory setup commands
output_directory_setup_cmds() {
    echo "Make sure the following directories exist and have appropriate permissions:"
    echo "mkdir -p /path/to/output_directory"
    echo "mkdir -p /path/to/log_directory"
    echo "Ensure the user running RLA has write permissions to these directories."
}

# Function to find Python 3 executable path
get_python_path() {
    PYTHON_BIN=$(which python3)
    if [ -z "$PYTHON_BIN" ]; then
        echo "Python 3 not found. Please ensure Python 3.8 or higher is installed."
        exit 1
    fi
    echo "$PYTHON_BIN"
}

# Function to output the command for creating a systemd service
output_systemd_setup_cmd() {
    PYTHON_PATH=$(get_python_path)
    SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

    echo "To create a systemd service for RLA, run the following commands:"
    cat << EOF > rla.service
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

    echo "sudo mv rla.service /etc/systemd/system/"
    echo "sudo systemctl daemon-reload"
    echo "sudo systemctl enable rla.service"
}

# Main setup instructions
check_python
check_pip3
install_requirements_cmd
output_directory_setup_cmds
output_systemd_setup_cmd

echo "Please ensure all the above steps are completed successfully."