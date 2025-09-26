#!/bin/bash

# WAF Build Validation Script
# This script checks that all necessary files exist for Docker builds

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_file() {
    local file="$1"
    local description="$2"

    if [ -f "$file" ]; then
        log_success "$description: ✓"
        return 0
    else
        log_error "$description: ✗ MISSING"
        return 1
    fi
}

check_directory() {
    local dir="$1"
    local description="$2"

    if [ -d "$dir" ]; then
        log_success "$description: ✓"
        return 0
    else
        log_error "$description: ✗ MISSING"
        return 1
    fi
}

validate_backend() {
    log_info "Validating backend build requirements..."

    local backend_dir="backend"
    local errors=0

    check_file "$backend_dir/go.mod" "Go module file" || errors=$((errors+1))
    check_file "$backend_dir/go.sum" "Go sum file" || errors=$((errors+1))
    check_file "$backend_dir/Dockerfile" "Backend Dockerfile" || errors=$((errors+1))
    check_file "$backend_dir/main.go" "Main Go file" || errors=$((errors+1))
    check_file "$backend_dir/database.go" "Database Go file" || errors=$((errors+1))
    check_file "$backend_dir/handlers.go" "Handlers Go file" || errors=$((errors+1))

    if [ $errors -eq 0 ]; then
        log_success "Backend validation: All files present"
    else
        log_error "Backend validation: $errors file(s) missing"
    fi

    return $errors
}

validate_dashboard() {
    log_info "Validating dashboard build requirements..."

    local dashboard_dir="dashboard"
    local errors=0

    check_file "$dashboard_dir/package.json" "Package.json file" || errors=$((errors+1))
    check_file "$dashboard_dir/package-lock.json" "Package lock file" || errors=$((errors+1))
    check_file "$dashboard_dir/Dockerfile" "Dashboard Dockerfile" || errors=$((errors+1))
    check_file "$dashboard_dir/next.config.js" "Next.js config" || errors=$((errors+1))
    check_file "$dashboard_dir/tsconfig.json" "TypeScript config" || errors=$((errors+1))
    check_file "$dashboard_dir/tailwind.config.ts" "Tailwind config" || errors=$((errors+1))

    # Check source files
    check_file "$dashboard_dir/src/app/layout.tsx" "Layout component" || errors=$((errors+1))
    check_file "$dashboard_dir/src/app/page.tsx" "Main page component" || errors=$((errors+1))
    check_file "$dashboard_dir/src/components/ui/card.tsx" "UI components" || errors=$((errors+1))

    if [ $errors -eq 0 ]; then
        log_success "Dashboard validation: All files present"
    else
        log_error "Dashboard validation: $errors file(s) missing"
    fi

    return $errors
}

validate_infrastructure() {
    log_info "Validating infrastructure files..."

    local errors=0

    check_file "docker-compose.yml" "Docker Compose file" || errors=$((errors+1))
    check_file "caddy/Caddyfile" "Caddy configuration" || errors=$((errors+1))
    check_file "install.sh" "Installation script" || errors=$((errors+1))
    check_file "setup.sh" "Setup script" || errors=$((errors+1))
    check_file "install-from-github.sh" "One-line installer" || errors=$((errors+1))
    check_file "README.md" "Documentation" || errors=$((errors+1))
    check_file ".gitignore" "Git ignore file" || errors=$((errors+1))

    if [ $errors -eq 0 ]; then
        log_success "Infrastructure validation: All files present"
    else
        log_error "Infrastructure validation: $errors file(s) missing"
    fi

    return $errors
}

validate_shared_types() {
    log_info "Validating shared types..."

    local errors=0

    check_file "shared/types.ts" "Shared TypeScript types" || errors=$((errors+1))

    if [ $errors -eq 0 ]; then
        log_success "Shared types validation: All files present"
    else
        log_error "Shared types validation: $errors file(s) missing"
    fi

    return $errors
}

main() {
    echo
    log_info "====================================="
    log_info "WAF Build Validation Script"
    log_info "====================================="
    echo

    local total_errors=0

    validate_backend || total_errors=$((total_errors + $?))
    echo

    validate_dashboard || total_errors=$((total_errors + $?))
    echo

    validate_infrastructure || total_errors=$((total_errors + $?))
    echo

    validate_shared_types || total_errors=$((total_errors + $?))
    echo

    if [ $total_errors -eq 0 ]; then
        log_success "====================================="
        log_success "All validations passed! ✓"
        log_success "The project is ready for Docker builds."
        log_success "====================================="
        echo
        log_info "You can now run:"
        log_info "  docker compose build"
        log_info "  docker compose up -d"
        echo
        log_info "Or use the installation scripts:"
        log_info "  ./setup.sh"
        log_info "  curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash"
    else
        log_error "====================================="
        log_error "Validation failed with $total_errors error(s) ✗"
        log_error "Please fix the missing files before building."
        log_error "====================================="
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
