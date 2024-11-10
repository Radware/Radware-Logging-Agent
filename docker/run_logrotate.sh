#!/bin/bash

# Loop forever, running logrotate every day
while :; do
    /usr/sbin/logrotate /etc/logrotate.d/rla
    # Sleep for 24 hours
    sleep 86400
done