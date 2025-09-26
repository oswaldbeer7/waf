#!/bin/bash

# WAF (Web Application Firewall) Multi-Domain Reverse Proxy Installer
# This script sets up a complete self-hosted reverse proxy with analytics and anti-bot protection

set -e

# Configuration
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
BACKUP_DIR="backup"

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

check_dependencies() {
    log_info "Checking system dependencies..."

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        log_info "If you haven't run the complete setup script, please use:"
        log_info "curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash"
        exit 1
    fi

    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed."
        log_info "If you haven't run the complete setup script, please use:"
        log_info "curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash"
        exit 1
    fi

    log_success "Dependencies check passed"
}

create_env_file() {
    if [ -f "$ENV_FILE" ]; then
        log_warning ".env file already exists. Skipping creation."
        return
    fi

    log_info "Creating .env file with default configuration..."

    cat > "$ENV_FILE" << 'EOF'
# WAF Configuration
COMPOSE_PROJECT_NAME=waf

# Backend Configuration
DB_PATH=/app/data/waf.db
CADDY_ADMIN_API=http://caddy:2019
LOG_LEVEL=info

# Dashboard Configuration
NEXT_PUBLIC_API_URL=http://localhost:8080

# Optional: Watchtower for automatic updates
WATCHTOWER_ENABLED=true

# Security Settings
# Change these in production
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123

# SSL/TLS Settings (for production)
# SSL_CERT_PATH=/path/to/certificate.pem
# SSL_KEY_PATH=/path/to/private.key
# ACME_EMAIL=your-email@example.com
EOF

    log_success "Created .env file with default configuration"
    log_warning "Please edit the .env file to customize your configuration"
    log_warning "Important: Change the default admin password!"
}

create_backup() {
    if [ -d "./data" ] || [ -f "./caddy/Caddyfile" ]; then
        log_info "Creating backup of existing data..."

        mkdir -p "$BACKUP_DIR"
        BACKUP_NAME="backup_$(date +%Y%m%d_%H%M%S)"

        if [ -d "./data" ]; then
            cp -r ./data "$BACKUP_DIR/$BACKUP_NAME"
        fi

        if [ -f "./caddy/Caddyfile" ]; then
            cp ./caddy/Caddyfile "$BACKUP_DIR/${BACKUP_NAME}_Caddyfile"
        fi

        log_success "Backup created: $BACKUP_DIR/$BACKUP_NAME"
    fi
}

build_images() {
    log_info "Building Docker images..."

    if command -v docker-compose &> /dev/null; then
        docker-compose build --no-cache
    else
        docker compose build --no-cache
    fi

    log_success "Docker images built successfully"
}

start_services() {
    log_info "Starting WAF services..."

    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi

    log_success "WAF services started successfully"

    # Wait for services to be healthy
    log_info "Waiting for services to be ready..."
    sleep 10

    # Check if services are running
    if command -v docker-compose &> /dev/null; then
        docker-compose ps
    else
        docker compose ps
    fi
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

create_initial_domain() {
    log_info "Creating initial domain configuration..."

    # Wait a bit more for the backend to be fully ready
    sleep 5

    SERVER_IP=$(detect_server_ip)

    # Create a default domain if the API is available
    if curl -s http://$SERVER_IP:8080/api/health &> /dev/null; then
        log_info "Backend API is ready. You can now configure domains through the dashboard."
    else
        log_warning "Backend API not yet available. Services are starting up."
        log_info "Please wait a few more moments, then visit http://$SERVER_IP:3000 to configure your first domain."
    fi
}

setup_firewall() {
    log_info "Setting up basic firewall rules..."

    # Basic firewall setup (optional)
    if command -v ufw &> /dev/null; then
        ufw allow 80
        ufw allow 443
        log_success "Firewall rules updated"
    else
        log_info "UFW not available. Skipping firewall configuration."
    fi
}

print_success_message() {
    # Detect server IP address
    SERVER_IP=$(detect_server_ip)

    echo
    log_success "======================================"
    log_success "WAF Installation Completed Successfully!"
    log_success "======================================"
    echo
    log_info "Your WAF is now running with the following services:"
    echo "  - Caddy Reverse Proxy: http://$SERVER_IP:80, https://$SERVER_IP:443"
    echo "  - Backend API: http://$SERVER_IP:8080"
    echo "  - Dashboard: http://$SERVER_IP:3000"
    echo
    log_info "Next steps:"
    echo "1. Visit http://$SERVER_IP:3000 to access the dashboard"
    echo "2. Add your first domain through the web interface"
    echo "3. Configure anti-bot rules as needed"
    echo
    log_info "Default login credentials:"
    echo "  Username: admin"
    echo "  Password: changeme123"
    log_warning "Please change the default password immediately!"
    echo
    log_info "For logs and data:"
    echo "  - Application logs: ./backend/logs/"
    echo "  - Database: ./backend/data/waf.db"
    echo "  - Caddy logs: ./caddy/logs/"
    echo
    log_info "To stop all services: ./stop.sh"
    log_info "To restart: docker-compose restart"
    log_info "To view logs: docker-compose logs -f"
}

main() {
    echo
    log_info "=========================================="
    log_info "WAF Multi-Domain Reverse Proxy Installer"
    log_info "=========================================="
    echo

    # Check if running as root (needed for some operations)
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root. This is not recommended for production."
    fi

    # Check dependencies
    check_dependencies

    # Create backup if needed
    create_backup

    # Create environment file
    create_env_file

    # Build images
    build_images

    # Start services
    start_services

    # Setup firewall (optional)
    setup_firewall

    # Create initial domain
    create_initial_domain

    # Print success message
    print_success_message

    log_success "Installation completed!"
}

# Check if this script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
