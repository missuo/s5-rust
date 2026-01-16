#!/bin/bash

# s5-rust Installation Script
# https://github.com/missuo/s5-rust

set -e

REPO="missuo/s5-rust"
REPO_URL="https://github.com/${REPO}"

# Ensure we can read user input even when piped
if [[ ! -t 0 ]]; then
    exec < /dev/tty
fi
BINARY_NAME="s5-rust"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="s5-rust"
CONFIG_DIR="/etc/s5-rust"
CONFIG_FILE="${CONFIG_DIR}/config"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "╔═════════════════════════════════════════════════╗"
    echo "║              s5-rust Manager                    ║"
    echo "║        SOCKS5 Proxy Server for Linux            ║"
    echo "║  https://github.com/missuo/s5-rust              ║"
    echo "╚═════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_menu() {
    echo -e "${GREEN}Please select an option:${NC}"
    echo ""
    echo "  1) Install"
    echo "  2) Uninstall"
    echo "  3) Update"
    echo "  4) Start"
    echo "  5) Stop"
    echo "  6) Restart"
    echo "  7) Enable Autostart"
    echo "  8) Disable Autostart"
    echo "  9) Show Status"
    echo "  0) Exit"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

check_system() {
    if [[ ! -f /etc/os-release ]]; then
        echo -e "${RED}Error: Cannot detect OS${NC}"
        exit 1
    fi

    if ! command -v systemctl &> /dev/null; then
        echo -e "${RED}Error: systemctl not found. This script requires systemd.${NC}"
        exit 1
    fi
}

get_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac
}

get_latest_version() {
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$latest_version" ]]; then
        echo -e "${RED}Error: Failed to get latest version${NC}"
        exit 1
    fi
    echo "$latest_version"
}

generate_random_string() {
    local length=${1:-16}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

download_binary() {
    local version=$1
    local arch=$(get_arch)
    local download_url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-linux-${arch}"

    echo -e "${BLUE}Downloading ${BINARY_NAME} ${version} for linux-${arch}...${NC}"

    if ! curl -L -o "/tmp/${BINARY_NAME}" "$download_url"; then
        echo -e "${RED}Error: Failed to download binary${NC}"
        exit 1
    fi

    chmod +x "/tmp/${BINARY_NAME}"
    mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

    echo -e "${GREEN}Binary installed to ${INSTALL_DIR}/${BINARY_NAME}${NC}"
}

create_service() {
    local username=$1
    local password=$2
    local port=$3

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=s5-rust SOCKS5 Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -u ${username} -p ${password} --port ${port}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}Systemd service created${NC}"
}

save_config() {
    local username=$1
    local password=$2
    local port=$3

    mkdir -p "${CONFIG_DIR}"
    cat > "${CONFIG_FILE}" << EOF
USERNAME=${username}
PASSWORD=${password}
PORT=${port}
EOF
    chmod 600 "${CONFIG_FILE}"
}

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        echo "$USERNAME $PASSWORD $PORT"
    fi
}

install() {
    echo -e "${BLUE}Starting installation...${NC}"
    echo ""

    # Check if already installed
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        echo -e "${YELLOW}Warning: ${BINARY_NAME} is already installed.${NC}"
        read -p "Do you want to reinstall? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Installation cancelled."
            return
        fi
        stop_service 2>/dev/null || true
    fi

    # Get latest version
    local version=$(get_latest_version)
    echo -e "${GREEN}Latest version: ${version}${NC}"
    echo ""

    # Get username
    read -p "Enter username (press Enter for random): " input_username
    if [[ -z "$input_username" ]]; then
        input_username=$(generate_random_string 8)
        echo -e "${YELLOW}Generated username: ${input_username}${NC}"
    fi

    # Get password
    read -p "Enter password (press Enter for random): " input_password
    if [[ -z "$input_password" ]]; then
        input_password=$(generate_random_string 16)
        echo -e "${YELLOW}Generated password: ${input_password}${NC}"
    fi

    # Get port
    read -p "Enter port (press Enter for default 1080): " input_port
    if [[ -z "$input_port" ]]; then
        input_port=1080
    fi

    echo ""

    # Download binary
    download_binary "$version"

    # Save config
    save_config "$input_username" "$input_password" "$input_port"

    # Create systemd service
    create_service "$input_username" "$input_password" "$input_port"

    # Start service
    systemctl start ${SERVICE_NAME}
    systemctl enable ${SERVICE_NAME}

    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Server:   0.0.0.0:${input_port}"
    echo -e "  Username: ${input_username}"
    echo -e "  Password: ${input_password}"
    echo ""
    echo -e "  Test command:"
    echo -e "  curl --socks5 127.0.0.1:${input_port} --proxy-user ${input_username}:${input_password} http://httpbin.org/ip"
    echo ""
}

uninstall() {
    echo -e "${BLUE}Starting uninstallation...${NC}"

    read -p "Are you sure you want to uninstall? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Uninstallation cancelled."
        return
    fi

    # Stop and disable service
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        systemctl stop ${SERVICE_NAME}
    fi
    if systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        systemctl disable ${SERVICE_NAME}
    fi

    # Remove service file
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload

    # Remove binary
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"

    # Remove config
    rm -rf "${CONFIG_DIR}"

    echo -e "${GREEN}Uninstallation completed successfully!${NC}"
}

update() {
    echo -e "${BLUE}Starting update...${NC}"

    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        echo -e "${RED}Error: ${BINARY_NAME} is not installed. Please install first.${NC}"
        return
    fi

    # Get latest version
    local version=$(get_latest_version)
    echo -e "${GREEN}Latest version: ${version}${NC}"

    # Stop service
    local was_running=false
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        was_running=true
        systemctl stop ${SERVICE_NAME}
    fi

    # Download new binary
    download_binary "$version"

    # Restart service if it was running
    if $was_running; then
        systemctl start ${SERVICE_NAME}
    fi

    echo -e "${GREEN}Update completed successfully!${NC}"
}

start_service() {
    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        echo -e "${RED}Error: ${BINARY_NAME} is not installed.${NC}"
        return
    fi

    systemctl start ${SERVICE_NAME}
    echo -e "${GREEN}Service started${NC}"
}

stop_service() {
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    echo -e "${GREEN}Service stopped${NC}"
}

restart_service() {
    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        echo -e "${RED}Error: ${BINARY_NAME} is not installed.${NC}"
        return
    fi

    systemctl restart ${SERVICE_NAME}
    echo -e "${GREEN}Service restarted${NC}"
}

enable_autostart() {
    if [[ ! -f /etc/systemd/system/${SERVICE_NAME}.service ]]; then
        echo -e "${RED}Error: Service not found. Please install first.${NC}"
        return
    fi

    systemctl enable ${SERVICE_NAME}
    echo -e "${GREEN}Autostart enabled${NC}"
}

disable_autostart() {
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    echo -e "${GREEN}Autostart disabled${NC}"
}

show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    echo ""

    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        echo -e "  Installed: ${RED}No${NC}"
        return
    fi

    echo -e "  Installed: ${GREEN}Yes${NC}"

    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "  Running:   ${GREEN}Yes${NC}"
    else
        echo -e "  Running:   ${RED}No${NC}"
    fi

    if systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "  Autostart: ${GREEN}Enabled${NC}"
    else
        echo -e "  Autostart: ${RED}Disabled${NC}"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        echo ""
        echo -e "  Port:      ${PORT}"
        echo -e "  Username:  ${USERNAME}"
        echo -e "  Password:  ${PASSWORD}"
    fi
}

main() {
    check_root
    check_system

    clear
    print_banner

    while true; do
        print_menu
        read -p "Enter option [0-9]: " choice
        echo ""

        case $choice in
            1)
                install
                ;;
            2)
                uninstall
                ;;
            3)
                update
                ;;
            4)
                start_service
                ;;
            5)
                stop_service
                ;;
            6)
                restart_service
                ;;
            7)
                enable_autostart
                ;;
            8)
                disable_autostart
                ;;
            9)
                show_status
                ;;
            0)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
        clear
        print_banner
    done
}

main "$@"
