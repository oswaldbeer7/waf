#!/bin/bash

# WAF (Web Application Firewall) Complete Setup Script
# This script installs all dependencies, clones the repository, and sets up the complete WAF system

set -e

# Configuration
REPO_URL="https://github.com/oswaldbeer7/waf.git"
REPO_DIR="waf"
WAF_INSTALL_SCRIPT="install.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root. This is not recommended for production."
        log_warning "Consider running as a regular user with sudo privileges."
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/debian_version ]; then
        OS="debian"
        PKG_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
        PKG_MANAGER="yum"
    elif [ -f /etc/os-release ]; then
        if grep -q "Ubuntu" /etc/os-release; then
            OS="ubuntu"
            PKG_MANAGER="apt"
        elif grep -q "CentOS" /etc/os-release; then
            OS="centos"
            PKG_MANAGER="yum"
        else
            OS="unknown"
            PKG_MANAGER="unknown"
        fi
    else
        OS="unknown"
        PKG_MANAGER="unknown"
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."

    case $PKG_MANAGER in
        "apt")
            sudo apt update && sudo apt upgrade -y
            ;;
        "yum")
            sudo yum update -y
            ;;
        *)
            log_error "Unsupported package manager: $PKG_MANAGER"
            exit 1
            ;;
    esac

    log_success "System packages updated"
}

# Install required packages
install_dependencies() {
    log_info "Installing required system dependencies..."

    case $PKG_MANAGER in
        "apt")
            sudo apt install -y \
                curl \
                wget \
                git \
                software-properties-common \
                apt-transport-https \
                ca-certificates \
                gnupg \
                lsb-release \
                sqlite3 \
                build-essential
            ;;
        "yum")
            sudo yum install -y \
                curl \
                wget \
                git \
                sqlite \
                gcc \
                make
            ;;
        *)
            log_error "Unsupported package manager: $PKG_MANAGER"
            exit 1
            ;;
    esac

    log_success "System dependencies installed"
}

# Install Docker
install_docker() {
    if command -v docker &> /dev/null; then
        log_success "Docker is already installed"
        return
    fi

    log_info "Installing Docker..."

    case $PKG_MANAGER in
        "apt")
            # Add Docker's official GPG key
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

            # Set up the stable repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

            # Install Docker Engine
            sudo apt update
            sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        "yum")
            # Install Docker using the convenience script
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo rm get-docker.sh
            ;;
    esac

    # Start and enable Docker
    sudo systemctl start docker
    sudo systemctl enable docker

    # Add current user to docker group (if not root)
    if [ "$EUID" -ne 0 ]; then
        sudo usermod -aG docker $USER
        log_warning "Added $USER to docker group. You may need to logout and login again for changes to take effect."
    fi

    log_success "Docker installed and configured"
}

# Install Node.js and npm
install_nodejs() {
    if command -v node &> /dev/null; then
        log_success "Node.js is already installed"
        return
    fi

    log_info "Installing Node.js and npm..."

    case $PKG_MANAGER in
        "apt")
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt install -y nodejs
            ;;
        "yum")
            curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
            sudo yum install -y nodejs
            ;;
    esac

    log_success "Node.js and npm installed"
}

# Install Go
install_go() {
    if command -v go &> /dev/null; then
        log_success "Go is already installed"
        return
    fi

    log_info "Installing Go..."

    local go_version="1.21.5"
    local go_os="linux"
    local go_arch="amd64"

    wget -q https://go.dev/dl/go${go_version}.${go_os}-${go_arch}.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${go_version}.${go_os}-${go_arch}.tar.gz
    rm go${go_version}.${go_os}-${go_arch}.tar.gz

    # Add Go to PATH
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi

    if ! grep -q "/usr/local/go/bin" ~/.profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    fi

    export PATH=$PATH:/usr/local/go/bin

    log_success "Go installed"
}

# Clone or update repository
setup_repository() {
    if [ -d "$REPO_DIR" ]; then
        log_info "Repository already exists. Updating..."
        cd "$REPO_DIR"
        git pull origin main || git pull origin master
        cd ..
    else
        log_info "Cloning repository..."
        git clone "$REPO_URL" "$REPO_DIR"
    fi

    log_success "Repository ready"
}

# Run WAF installation
install_waf() {
    log_info "Starting WAF installation..."

    cd "$REPO_DIR"

    # Make scripts executable
    chmod +x "$WAF_INSTALL_SCRIPT" stop.sh test-installation.sh

    # Check if we should run with sudo
    if [ "$EUID" -eq 0 ]; then
        ./"$WAF_INSTALL_SCRIPT"
    else
        # Run as current user but with sudo for docker commands
        sudo -E ./"$WAF_INSTALL_SCRIPT"
    fi

    log_success "WAF installation completed"
}

# Create desktop shortcuts (optional)
create_shortcuts() {
    log_info "Creating desktop shortcuts..."

    local desktop_dir="$HOME/Desktop"
    local shortcut_path="$desktop_dir/waf-dashboard.desktop"

    if [ -d "$desktop_dir" ]; then
        cat > "$shortcut_path" << EOF
[Desktop Entry]
Version=1.0
Name=WAF Dashboard
Comment=Multi-Domain Reverse Proxy & Analytics Dashboard
GenericName=Web Application Firewall
Keywords=WAF;Proxy;Analytics;Security
Exec=xdg-open http://$SERVER_IP:3000
Icon=web-browser
Terminal=false
Type=Application
Categories=Network;Security;WebDevelopment
EOF

        chmod +x "$shortcut_path"
        log_success "Desktop shortcut created"
    fi
}

# Main installation function
main() {
    echo
    log_info "====================================="
    log_info "WAF Complete Setup Script"
    log_info "====================================="
    echo

    # Check if running as root
    check_root

    # Detect OS
    detect_os
    log_info "Detected OS: $OS"
    log_info "Package manager: $PKG_MANAGER"

    # Update system
    update_system

    # Install dependencies
    install_dependencies

    # Install Docker
    install_docker

    # Install Node.js
    install_nodejs

    # Install Go
    install_go

    # Setup repository
    setup_repository

    # Install WAF
    install_waf

    # Create shortcuts
    create_shortcuts

    # Print success message
    echo
    log_success "====================================="
    log_success "WAF Setup Completed Successfully!"
    log_success "====================================="
    echo
    SERVER_IP=$(detect_server_ip)

    log_info "Your WAF system is now installed and running!"
    echo
    log_info "Access points:"
    echo "  - Dashboard: http://$SERVER_IP:3000"
    log_info "  - API: http://$SERVER_IP:8080"
    echo "  - Proxy: http://$SERVER_IP (for configured domains)"
    echo
    log_info "To manage services:"
    echo "  - Stop all services: cd $REPO_DIR && ./stop.sh"
    echo "  - Test installation: cd $REPO_DIR && ./test-installation.sh"
    echo "  - View logs: cd $REPO_DIR && docker-compose logs -f"
    echo
    log_info "Default login credentials:"
    echo "  - Username: admin"
    echo "  - Password: changeme123"
    log_warning "Please change the default password immediately!"
    echo
    log_info "For documentation and support:"
    echo "  - README: $REPO_DIR/README.md"
    echo "  - Repository: $REPO_URL"
    echo
    log_info "Note: If you were added to the docker group, you may need to logout and login again."
}

detect_server_ip() {
    # Try to detect the primary network interface IP
    # First try to get IP from default route
    IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)

    if [ -z "$IP" ] || [ "$IP" = "" ]; then
        # Fallback to hostname resolution
        IP=$(hostname -I 2>/dev/null | awk '{print $1}' | head -1)
    fi

    if [ -z "$IP" ] || [ "$IP" = "" ]; then
        # Final fallback to localhost
        IP="localhost"
    fi

    echo "$IP"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
