#!/bin/bash

# WAF Stop Script
# This script stops all WAF services gracefully

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

stop_services() {
    log_info "Stopping WAF services..."

    if [ -f "docker-compose.yml" ]; then
        if command -v docker-compose &> /dev/null; then
            docker-compose down
        else
            docker compose down
        fi
        log_success "All services stopped successfully"
    else
        log_error "docker-compose.yml not found"
        exit 1
    fi
}

cleanup_containers() {
    log_info "Cleaning up containers and networks..."

    # Remove any orphaned containers
    if command -v docker-compose &> /dev/null; then
        docker-compose down --remove-orphans --volumes --rmi local 2>/dev/null || true
    else
        docker compose down --remove-orphans --volumes --rmi local 2>/dev/null || true
    fi

    log_success "Cleanup completed"
}

main() {
    echo
    log_info "=================================="
    log_info "WAF Service Stop Script"
    log_info "=================================="
    echo

    # Stop services
    stop_services

    # Cleanup
    cleanup_containers

    echo
    log_success "All WAF services have been stopped and cleaned up"
    log_info "To start services again: ./install.sh"
    log_info "To remove all data: rm -rf ./data ./caddy/data ./caddy/logs ./backend/data"
}

# Check if this script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
