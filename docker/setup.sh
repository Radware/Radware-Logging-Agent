#!/bin/bash

export RLA_ENVIRONMENT=docker
# Determine the configuration source
CONFIGURATION_SOURCE="${CONFIGURATION_SOURCE:-env}" # Defaults to "env" if not set

if [[ "$CONFIGURATION_SOURCE" == "s3" ]]; then
    # --- S3 Configuration Section ---
    # This section only happens if configured to use S3, based on the CONFIGURATION_SOURCE variable
    echo "Downloading configuration file from S3"
    if [ -z "$S3_BUCKET" ] || [ -z "$S3_KEY" ]; then
        echo "Error: S3_BUCKET and S3_KEY environment variables must be set for S3 configuration" >&2
        exit 1
    fi

    # Use IAM role for accessing S3 (credentials are automatically provided in ECS environment)
    aws s3 cp s3://$S3_BUCKET/$S3_KEY /usr/src/app/rla.yaml
    if [ $? -ne 0 ]; then
        echo "Error: Failed to download configuration file from S3" >&2
        exit 1
    fi

    echo "S3 configuration file downloaded successfully."

    # ---- End of S3 Section ----

else
    # --- Environment Variable Configuration Section ---
    # This section runs if the configuration is set to use environment variables or is the default

    # Read environment variables and replace placeholders in rla.yaml.template
    echo "Populating rla.yaml.template with environment variables..."
    cp rla.yaml.template rla.yaml

    # Replace placeholders in rla.yaml with environment variable values or default values
    while IFS= read -r line; do
        while [[ "$line" =~ (\$\{([a-zA-Z_][a-zA-Z0-9_]*)(:-([^}]*))?\}) ]]; do
            whole_match="${BASH_REMATCH[1]}"
            var_name="${BASH_REMATCH[2]}"
            default_value="${BASH_REMATCH[4]}"

            # Check if the environment variable exists
            if [[ -n "${!var_name}" ]]; then
                value="${!var_name}"
            else
                value="${default_value}"
            fi

            # Escape ampersands for parameter substitution
            value="${value//&/\\&}"

            # Replace the placeholder with the actual value
            line="${line//$whole_match/$value}"
        done
        # Print modified line to the rla.yaml file
        echo "$line"
    done < rla.yaml.template > rla.yaml

    # Verify the output
    echo "Contents of the generated rla.yaml:"

    # Verify critical variables are set in the generated rla.yaml
    CRITICAL_VARS=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY")

    for var in "${CRITICAL_VARS[@]}"; do
        if grep -q "\${${var}}" rla.yaml; then
            echo "Error: Critical variable ${var} not replaced in rla.yaml. Please check environment variables." >&2
            exit 1
        fi
    done

    echo "Applying dynamic custom header configuration from environment variables (if provided)..."
    python <<'PY'
import os
import re
from pathlib import Path

import yaml


CONFIG_PATH = Path("rla.yaml")


def normalise_header_name(raw_name: str) -> str:
    return raw_name.replace("_", "-")


def extract_headers(protocol: str) -> dict[str, str]:
    prefix = protocol.upper()
    headers: dict[str, str] = {}

    custom_headers_env = os.getenv(f"{prefix}_CUSTOM_HEADERS")
    if custom_headers_env:
        for pair in custom_headers_env.split(";"):
            if not pair.strip() or "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name = name.strip()
            value = value.strip()
            if name:
                headers[name] = value

    pattern_prefix = re.compile(rf"^{prefix}_(?:CUSTOM_HEADER_|HEADER_)(.+)$")
    pattern_suffix = re.compile(rf"^{prefix}_(.+)_HEADER$")

    for env_name, env_value in os.environ.items():
        if not env_value:
            continue
        match = pattern_prefix.match(env_name)
        if match is None:
            match = pattern_suffix.match(env_name)
        if match is None:
            continue
        header_key = normalise_header_name(match.group(1))
        headers[header_key] = env_value

    return headers


if CONFIG_PATH.exists():
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}
else:
    config = {}

for protocol in ("http", "https"):
    headers = extract_headers(protocol)
    if not headers:
        continue
    section = config.setdefault(protocol, {})
    section["custom_headers"] = headers

with CONFIG_PATH.open("w", encoding="utf-8") as fh:
    yaml.safe_dump(config, fh, sort_keys=False)
PY

    # ---- End of Environment Variable Section ----
fi

# Start the application
echo "Starting Radware Logging Agent..."
exec python ./src/radware_logging_agent.py
