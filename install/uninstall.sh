#!/usr/bin/env bash

set -euo pipefail

APP_DIR_DEFAULT="/etc/rla"
LOG_DIR_DEFAULT="/var/log/rla"
SERVICE_NAME_DEFAULT="rla"
SERVICE_USER_DEFAULT="rla"
SERVICE_GROUP_DEFAULT="rla"
LOGROTATE_FILE_DEFAULT="/etc/logrotate.d/rla"

APP_DIR="$APP_DIR_DEFAULT"
LOG_DIR="$LOG_DIR_DEFAULT"
SERVICE_NAME="$SERVICE_NAME_DEFAULT"
SERVICE_USER="$SERVICE_USER_DEFAULT"
SERVICE_GROUP="$SERVICE_GROUP_DEFAULT"
LOGROTATE_FILE="$LOGROTATE_FILE_DEFAULT"
PRESERVE_APP_DIR=false
PRESERVE_LOGS=false
PRESERVE_USER=false
NON_INTERACTIVE=false
YES=false

usage() {
    cat <<EOF
Radware Logging Agent uninstaller

Usage: sudo $(basename "$0") [options]

Options:
  --app-dir PATH          Installation directory (default: $APP_DIR_DEFAULT)
  --log-dir PATH          Log directory to remove (default: $LOG_DIR_DEFAULT)
  --service-name NAME     Systemd service name without suffix (default: $SERVICE_NAME_DEFAULT)
  --service-user USER     Service user to remove (default: $SERVICE_USER_DEFAULT)
  --service-group GROUP   Service group to remove (default: $SERVICE_GROUP_DEFAULT)
  --logrotate-file PATH   Logrotate config path (default: $LOGROTATE_FILE_DEFAULT)
  --preserve-app-dir      Do not delete the application directory
  --preserve-logs         Do not delete the log directory
  --preserve-user         Keep the service user and group
  --non-interactive       Do not show prompts (implies --yes)
  --yes                   Skip confirmation prompt
  --help                  Show this help message and exit
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
            --log-dir)
                LOG_DIR="$2"
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
            --logrotate-file)
                LOGROTATE_FILE="$2"
                shift 2
                ;;
            --preserve-app-dir)
                PRESERVE_APP_DIR=true
                shift
                ;;
            --preserve-logs)
                PRESERVE_LOGS=true
                shift
                ;;
            --preserve-user)
                PRESERVE_USER=true
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                YES=true
                shift
                ;;
            --yes)
                YES=true
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

confirm_action() {
    local prompt="$1"
    if [[ "$YES" == true ]]; then
        return
    fi

    read -r -p "$prompt [y/N]: " answer
    case "$answer" in
        [Yy]*) ;;
        *) log "Aborted by user."; exit 0 ;;
    esac
}

stop_service() {
    local service_unit="${SERVICE_NAME%.service}.service"

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "$service_unit"; then
            log "Stopping systemd service $service_unit..."
            systemctl stop "$service_unit"
        else
            log "Service $service_unit not running."
        fi

        if systemctl is-enabled --quiet "$service_unit"; then
            log "Disabling systemd service $service_unit..."
            systemctl disable "$service_unit"
        fi

        if [[ -f "/etc/systemd/system/$service_unit" ]]; then
            log "Removing service unit /etc/systemd/system/$service_unit..."
            rm -f "/etc/systemd/system/$service_unit"
            systemctl daemon-reload
        fi
    else
        log "systemctl not found. Skipping service stop/disable steps."
    fi
}

remove_logrotate() {
    if [[ -f "$LOGROTATE_FILE" ]]; then
        log "Removing logrotate configuration $LOGROTATE_FILE..."
        rm -f "$LOGROTATE_FILE"
    fi
}

remove_app_dir() {
    if [[ "$PRESERVE_APP_DIR" == true ]]; then
        log "Preserving application directory $APP_DIR as requested."
        return
    fi

    if [[ -d "$APP_DIR" ]]; then
        log "Removing application directory $APP_DIR..."
        rm -rf "$APP_DIR"
    else
        log "Application directory $APP_DIR not present."
    fi
}

remove_logs() {
    if [[ "$PRESERVE_LOGS" == true ]]; then
        log "Preserving log directory $LOG_DIR as requested."
        return
    fi

    if [[ -d "$LOG_DIR" ]]; then
        log "Removing log directory $LOG_DIR..."
        rm -rf "$LOG_DIR"
    else
        log "Log directory $LOG_DIR not present."
    fi
}

remove_user_and_group() {
    if [[ "$PRESERVE_USER" == true ]]; then
        log "Preserving service user and group as requested."
        return
    fi

    if id "$SERVICE_USER" >/dev/null 2>&1; then
        local processes
        processes=$(pgrep -u "$SERVICE_USER" || true)
        if [[ -n "$processes" ]]; then
            log "Terminating remaining processes owned by $SERVICE_USER..."
            pkill -u "$SERVICE_USER" || true
        fi

        log "Removing user $SERVICE_USER..."
        userdel "$SERVICE_USER" || log "Failed to remove user $SERVICE_USER (it may be in use)."
    fi

    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        log "Removing group $SERVICE_GROUP..."
        groupdel "$SERVICE_GROUP" || log "Failed to remove group $SERVICE_GROUP (it may be in use)."
    fi
}

remove_symlinks() {
    local service_unit="${SERVICE_NAME%.service}.service"
    local sysd_wants="/etc/systemd/system/multi-user.target.wants/${service_unit}"
    if [[ -L "$sysd_wants" ]]; then
        log "Removing systemd symlink $sysd_wants..."
        rm -f "$sysd_wants"
    fi
}

print_summary() {
    cat <<EOF

Radware Logging Agent removal complete.

Actions performed:
  - Stopped and disabled service:    ${SERVICE_NAME%.service}.service
  - Removed service files (if present)
  - Removed logrotate config:        ${LOGROTATE_FILE} $( [[ "$PRESERVE_LOGS" == true ]] && echo "(preserved)" )
  - Removed application directory:   ${APP_DIR} $( [[ "$PRESERVE_APP_DIR" == true ]] && echo "(preserved)" )
  - Removed log directory:           ${LOG_DIR} $( [[ "$PRESERVE_LOGS" == true ]] && echo "(preserved)" )
  - Removed user/group:              ${SERVICE_USER}/${SERVICE_GROUP} $( [[ "$PRESERVE_USER" == true ]] && echo "(preserved)" )

If additional spool directories were created (for example /var/spool/rla), remove them manually if no longer needed.
EOF
}

main() {
    parse_args "$@"
    require_root

    if [[ "$YES" == false ]]; then
        confirm_action "This will uninstall the Radware Logging Agent from ${APP_DIR}. Continue?"
    fi

    stop_service
    remove_symlinks
    remove_logrotate
    remove_app_dir
    remove_logs
    remove_user_and_group
    print_summary
}

main "$@"
