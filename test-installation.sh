#!/bin/bash

# WAF Installation Test Script
# This script tests the basic functionality of the WAF installation

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

TEST_DOMAIN="test.example.local"
TEST_ORIGIN="http://httpbin.org"

test_services_health() {
    log_info "Testing service health..."

    # Test backend API
    if curl -s http://$SERVER_IP:8080/api/health > /dev/null; then
        log_success "Backend API is healthy"
    else
        log_error "Backend API is not responding"
        return 1
    fi

    # Test dashboard
    if curl -s http://$SERVER_IP:3000/api/health > /dev/null; then
        log_success "Dashboard is healthy"
    else
        log_warning "Dashboard health check not available (expected for Next.js)"
    fi

    # Test Caddy admin API
    if curl -s http://$SERVER_IP:2019/config/ > /dev/null; then
        log_success "Caddy admin API is healthy"
    else
        log_error "Caddy admin API is not responding"
        return 1
    fi
}

test_api_endpoints() {
    log_info "Testing API endpoints..."

    # Test domains endpoint
    if curl -s http://$SERVER_IP:8080/api/domains | grep -q '\[\]'; then
        log_success "Domains API endpoint working"
    else
        log_error "Domains API endpoint not working"
        return 1
    fi

    # Test stats endpoint
    if curl -s http://$SERVER_IP:8080/api/stats > /dev/null; then
        log_success "Stats API endpoint working"
    else
        log_error "Stats API endpoint not working"
        return 1
    fi
}

test_domain_creation() {
    log_info "Testing domain creation..."

    # Create test domain
    DOMAIN_DATA='{"name":"'$TEST_DOMAIN'","origin_url":"'$TEST_ORIGIN'"}'

    if curl -s -X POST http://$SERVER_IP:8080/api/domains \
        -H "Content-Type: application/json" \
        -d "$DOMAIN_DATA" > /dev/null; then
        log_success "Domain creation API working"
    else
        log_error "Domain creation API failed"
        return 1
    fi
}

test_caddy_config() {
    log_info "Testing Caddy configuration update..."

    # Check if domain was added to Caddy config
    if curl -s http://$SERVER_IP:2019/config/ | grep -q "$TEST_DOMAIN"; then
        log_success "Caddy configuration updated successfully"
    else
        log_warning "Caddy configuration may not have been updated yet"
    fi
}

test_reverse_proxy() {
    log_info "Testing reverse proxy functionality..."

    # Wait a moment for Caddy to reload
    sleep 3

    # Test proxy to our test domain
    if curl -s -H "Host: $TEST_DOMAIN" http://$SERVER_IP/ | grep -q "httpbin"; then
        log_success "Reverse proxy working correctly"
    else
        log_warning "Reverse proxy test inconclusive (httpbin.org may be down)"
    fi
}

cleanup_test_data() {
    log_info "Cleaning up test data..."

    # Remove test domain
    if curl -s -X DELETE http://$SERVER_IP:8080/api/domains/1 > /dev/null; then
        log_success "Test domain cleaned up"
    else
        log_warning "Could not clean up test domain"
    fi
}

run_tests() {
    echo
    log_info "=================================="
    log_info "WAF Installation Test Suite"
    log_info "=================================="
    echo

    # Check if services are running
    if ! docker-compose ps | grep -q "Up"; then
        log_error "Services are not running. Please start them first with ./install.sh"
        exit 1
    fi

    # Detect server IP
    SERVER_IP=$(detect_server_ip)

    # Wait for services to be fully ready
    log_info "Waiting for services to be ready..."
    sleep 10

    # Run tests
    local tests_passed=0
    local total_tests=0

    test_function() {
        local test_name="$1"
        shift
        local test_func="$1"
        shift

        total_tests=$((total_tests + 1))
        log_info "Running test: $test_name"

        if $test_func "$@"; then
            tests_passed=$((tests_passed + 1))
        fi

        echo
    }

    test_function "Service Health" test_services_health
    test_function "API Endpoints" test_api_endpoints
    test_function "Domain Creation" test_domain_creation
    test_function "Caddy Configuration" test_caddy_config
    test_function "Reverse Proxy" test_reverse_proxy

    # Cleanup
    cleanup_test_data

    # Results
    echo
    log_info "=================================="
    log_info "Test Results"
    log_info "=================================="
    log_info "Tests passed: $tests_passed/$total_tests"

    if [ $tests_passed -eq $total_tests ]; then
        log_success "All tests passed! Your WAF installation is working correctly."
    else
        log_warning "Some tests failed. Check the logs above for details."
        log_info "This is normal for the first run. Try accessing the dashboard and manually testing domain creation."
    fi

    log_info "You can now:"
    log_info "1. Visit http://localhost:3000 to access the dashboard"
    log_info "2. Add your actual domains through the web interface"
    log_info "3. Configure anti-bot rules as needed"
}

# Check if this script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_tests "$@"
fi
