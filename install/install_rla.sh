#!/usr/bin/env bash

set -euo pipefail

APP_DIR_DEFAULT="/etc/rla"
SERVICE_NAME_DEFAULT="rla"
SERVICE_USER_DEFAULT="rla"
SERVICE_GROUP_DEFAULT="rla"
CONFIG_TEMPLATE="config/rla.yaml"

APP_DIR="$APP_DIR_DEFAULT"
SERVICE_NAME="$SERVICE_NAME_DEFAULT"
SERVICE_UNIT=""
SERVICE_USER="$SERVICE_USER_DEFAULT"
SERVICE_GROUP="$SERVICE_GROUP_DEFAULT"
CONFIG_SOURCE=""
VENV_DIR=""
NON_INTERACTIVE=false
FORCE_CONFIG=false
SKIP_DEPS=false
INSTALL_SERVICE=true
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<EOF
Radware Logging Agent installer

Usage: sudo $(basename "$0") [options]

Options:
  --app-dir PATH           Target installation directory (default: $APP_DIR_DEFAULT)
  --service-name NAME      systemd service name without suffix (default: $SERVICE_NAME_DEFAULT)
  --service-user USER      Unix user that will run the service (default: $SERVICE_USER_DEFAULT)
  --service-group GROUP    Unix group that will run the service (default: $SERVICE_GROUP_DEFAULT)
  --config PATH            Path to rla.yaml to deploy (defaults to keeping existing or template)
  --venv-dir PATH          Custom virtual environment directory (default: <app-dir>/venv)
  --non-interactive        Do not prompt, preserve existing config unless --force-config is set
  --force-config           Overwrite existing configuration with template or --config file
  --skip-deps              Skip package-manager dependency installation
  --no-service             Install files only; print manual service steps
  --help                   Show this message
EOF
}

log() {
    printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

fatal() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        fatal "This script must be run as root. Try again with sudo."
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --app-dir)
                APP_DIR="$2"
                shift 2
                ;;
            --service-name)
                SERVICE_NAME="$2"
                shift 2
                ;;
            --service-user)
                SERVICE_USER="$2"
                shift 2
                ;;
            --service-group)
                SERVICE_GROUP="$2"
                shift 2
                ;;
            --config)
                CONFIG_SOURCE="$2"
                shift 2
                ;;
            --venv-dir)
                VENV_DIR="$2"
                shift 2
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --force-config)
                FORCE_CONFIG=true
                shift
                ;;
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --no-service)
                INSTALL_SERVICE=false
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fatal "Unknown option: $1"
                ;;
        esac
    done
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo ""
    fi
}

ensure_dependencies() {
    if [[ "$SKIP_DEPS" == true ]]; then
        log "Skipping dependency installation as requested."
        return
    fi

    local pkg_manager
    pkg_manager=$(detect_pkg_manager)

    if [[ -z "$pkg_manager" ]]; then
        log "No supported package manager detected. Ensure python3, python3-venv, python3-pip, and rsync are installed."
        return
    fi

    log "Ensuring python3, python3-venv, python3-pip, and rsync are installed..."
    case "$pkg_manager" in
        apt)
            apt-get update
            apt-get install -y python3 python3-venv python3-pip rsync
            ;;
        dnf)
            dnf install -y python3 python3-pip python3-virtualenv rsync || dnf install -y python3 python3-pip python3-venv rsync
            ;;
        yum)
            yum install -y python3 python3-pip python3-venv rsync || yum install -y python3 python3-pip python3-virtualenv rsync
            ;;
        zypper)
            zypper --non-interactive install python3 python3-pip python311-venv rsync || true
            ;;
        apk)
            apk add --no-cache python3 py3-pip py3-virtualenv rsync
            ;;
    esac
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        fatal "Python 3 is required but not installed."
    fi
    if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3,8) else 1)'; then
        fatal "Python 3.8 or higher is required."
    fi
}

create_system_user() {
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        log "Creating group $SERVICE_GROUP..."
        groupadd "$SERVICE_GROUP"
    fi

    if id "$SERVICE_USER" >/dev/null 2>&1; then
        log "Service user $SERVICE_USER already exists."
        usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER" || true
        usermod -g "$SERVICE_GROUP" "$SERVICE_USER" || true
        return
    fi

    log "Creating system user $SERVICE_USER..."
    if command -v useradd >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d "/home/$SERVICE_USER" -m -g "$SERVICE_GROUP" "$SERVICE_USER"
    elif command -v adduser >/dev/null 2>&1; then
        adduser --system --ingroup "$SERVICE_GROUP" --home "/home/$SERVICE_USER" "$SERVICE_USER"
    else
        fatal "Cannot create user. Neither useradd nor adduser is available."
    fi
}

confirm_overwrite_config() {
    local dest_config="$APP_DIR/rla.yaml"

    if [[ "$FORCE_CONFIG" == true ]]; then
        return
    fi

    if [[ -f "$dest_config" && -z "$CONFIG_SOURCE" ]]; then
        if [[ "$NON_INTERACTIVE" == true ]]; then
            log "Existing configuration detected; preserving current rla.yaml (non-interactive mode)."
        else
            read -r -p "Existing configuration found. Overwrite with bundled template? [y/N]: " answer
            case "$answer" in
                [Yy]*) FORCE_CONFIG=true ;;
                *) log "Preserving existing configuration." ;;
            esac
        fi
    fi
}

sync_files() {
    mkdir -p "$APP_DIR"
    local excludes=(--exclude '.git' --exclude '.github' --exclude 'tests' --exclude 'extras/ecs/.DS_Store')

    log "Synchronizing application files to $APP_DIR..."
    if command -v rsync >/dev/null 2>&1; then
        rsync -a "${excludes[@]}" "$REPO_ROOT"/ "$APP_DIR"/
    else
        log "rsync not found; falling back to cp -R (some exclusions may be ignored)."
        cp -R "$REPO_ROOT"/* "$APP_DIR"
    fi
}

deploy_config() {
    local dest_config="$APP_DIR/rla.yaml"

    if [[ "$FORCE_CONFIG" == false && -f "$dest_config" && -z "$CONFIG_SOURCE" ]]; then
        log "Preserving existing configuration at $dest_config."
        return
    fi

    local source_config="$CONFIG_SOURCE"
    if [[ -z "$source_config" ]]; then
        source_config="$REPO_ROOT/$CONFIG_TEMPLATE"
    fi

    if [[ ! -f "$source_config" ]]; then
        fatal "Configuration source file not found at $source_config."
    fi

    log "Copying configuration from $source_config to $dest_config"
    cp "$source_config" "$dest_config"
    chown "$SERVICE_USER":"$SERVICE_GROUP" "$dest_config"
    chmod 640 "$dest_config"
}

link_config_into_src() {
    local src_link="$APP_DIR/src/rla.yaml"
    local root_config="$APP_DIR/rla.yaml"

    if [[ ! -f "$root_config" && -f "$src_link" ]]; then
        log "Root configuration file ${root_config} missing; leaving existing ${src_link} in place."
        return
    fi

    if [[ -e "$src_link" && ! -L "$src_link" ]]; then
        local backup="${src_link}.dist"
        log "Backing up existing ${src_link} to ${backup}"
        mv "$src_link" "$backup"
    fi

    ln -sfn ../rla.yaml "$src_link"
    chown -h "$SERVICE_USER":"$SERVICE_GROUP" "$src_link"
}

setup_directories() {
    mkdir -p "$APP_DIR" "/var/log/rla"
    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_GROUP" /var/log/rla
}

setup_virtualenv() {
    local requirements_file="$APP_DIR/requirements.txt"
    if [[ ! -f "$requirements_file" ]]; then
        fatal "requirements.txt not found in $APP_DIR. Ensure you ran the installer from the project root."
    fi

    if [[ -z "$VENV_DIR" ]]; then
        VENV_DIR="$APP_DIR/venv"
    fi

    log "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install --no-cache-dir -r "$requirements_file"

    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$VENV_DIR"
}

setup_logrotate() {
    log "Configuring log rotation..."
    cat > /etc/logrotate.d/rla <<EOF
/var/log/rla/*.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 640 ${SERVICE_USER} ${SERVICE_GROUP}
}
EOF
}

setup_systemd_service() {
    SERVICE_UNIT="${SERVICE_NAME%.service}.service"

    if [[ "$INSTALL_SERVICE" == false ]]; then
        log "Skipping systemd service installation (--no-service)."
        cat <<EOF
To start the agent manually:
  sudo -u ${SERVICE_USER} ${VENV_DIR}/bin/python ${APP_DIR}/src/radware_logging_agent.py

Recommended systemd service file (place in /etc/systemd/system/${SERVICE_UNIT}):
[Unit]
Description=Radware Logging Agent
After=network.target

[Service]
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${APP_DIR}
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/src/radware_logging_agent.py
Restart=on-failure

[Install]
wantedBy=multi-user.target
EOF
        return
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        fatal "systemctl not found. Re-run with --no-service and configure supervision manually."
    fi

    log "Writing systemd service definition to /etc/systemd/system/${SERVICE_UNIT}"
    cat > "/etc/systemd/system/${SERVICE_UNIT}" <<EOF
[Unit]
Description=Radware Logging Agent
After=network.target

[Service]
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${APP_DIR}
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/src/radware_logging_agent.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_UNIT}"
    systemctl restart "${SERVICE_UNIT}"
}

print_summary() {
    SERVICE_UNIT="${SERVICE_NAME%.service}.service"

    cat <<EOF

Radware Logging Agent installation complete.

- Installation directory: ${APP_DIR}
- Virtual environment:    ${VENV_DIR}
- Service name:           ${SERVICE_UNIT}
- Service user/group:     ${SERVICE_USER}/${SERVICE_GROUP}

Manage the service with:
  sudo systemctl status ${SERVICE_UNIT}
  sudo systemctl restart ${SERVICE_UNIT}

Configuration file:
  ${APP_DIR}/rla.yaml (linked at ${APP_DIR}/src/rla.yaml)

Logs:
  /var/log/rla/
EOF
}

main() {
    parse_args "$@"
    require_root
    ensure_dependencies
    check_python
    create_system_user
    confirm_overwrite_config
    sync_files
    deploy_config
    link_config_into_src
    setup_directories
    setup_virtualenv
    setup_logrotate
    setup_systemd_service
    print_summary
}

main "$@"
