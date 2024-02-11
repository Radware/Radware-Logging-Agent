#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

SERVICE_NAME="rla.service"
APP_DIR="/etc/rla"
LOG_DIR="/var/log/rla"
USER_NAME="rla"

# Stop and disable the systemd service
echo "Stopping and disabling $SERVICE_NAME..."
systemctl stop $SERVICE_NAME
systemctl disable $SERVICE_NAME

# Remove the systemd service file
echo "Removing the systemd service file..."
rm -f /etc/systemd/system/$SERVICE_NAME
systemctl daemon-reload

# Remove application and log directories
echo "Removing $APP_DIR and $LOG_DIR..."
rm -rf $APP_DIR
rm -rf $LOG_DIR

# Remove the 'rla' user and group
# Note: This will remove the user and group without removing the user's home directory
# If the user's home directory was created specifically for this service and is not needed,
# you might want to consider removing it as well.
echo "Removing the 'rla' user and group..."
userdel $USER_NAME
getent group $USER_NAME && groupdel $USER_NAME

echo "Cleanup completed."
