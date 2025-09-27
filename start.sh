#!/bin/bash

# WAF Reverse Proxy Startup Script
# This script configures and starts the WAF Reverse Proxy with proper environment variables

set -e  # Exit on any error

echo "=== WAF Reverse Proxy Startup ==="
echo ""

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --email EMAIL          ACME email for Let's Encrypt (default: admin@example.com)"
    echo "  --domain-port PORT     Domain HTTP port (default: 80)"
    echo "  --domain-https-port PORT  Domain HTTPS port (default: 443)"
    echo "  --mgmt-port PORT       Management HTTP port (default: 3000)"
    echo "  --mgmt-https-port PORT Management HTTPS port (default: 8443)"
    echo "  --log-level LEVEL      Log level: debug, info, warn, error (default: info)"
    echo "  --log-format FORMAT    Log format: text, json (default: text)"
    echo "  --rate-limit LIMIT     Rate limit per minute (default: 100)"
    echo "  --no-captcha          Disable captcha protection"
    echo "  --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --email admin@example.com --log-level debug"
    echo "  $0 --domain-port 8080 --mgmt-port 3001 --rate-limit 50"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --email)
            ACME_EMAIL="$2"
            shift 2
            ;;
        --domain-port)
            DOMAIN_HTTP_PORT="$2"
            shift 2
            ;;
        --domain-https-port)
            DOMAIN_HTTPS_PORT="$2"
            shift 2
            ;;
        --mgmt-port)
            MGMT_HTTP_PORT="$2"
            shift 2
            ;;
        --mgmt-https-port)
            MGMT_HTTPS_PORT="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --log-format)
            LOG_FORMAT="$2"
            shift 2
            ;;
        --rate-limit)
            RATE_LIMIT="$2"
            shift 2
            ;;
        --no-captcha)
            ENABLE_CAPTCHA="false"
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set default values
ACME_EMAIL=${ACME_EMAIL:-"admin@example.com"}
DOMAIN_HTTP_PORT=${DOMAIN_HTTP_PORT:-"80"}
DOMAIN_HTTPS_PORT=${DOMAIN_HTTPS_PORT:-"443"}
MGMT_HTTP_PORT=${MGMT_HTTP_PORT:-"3000"}
MGMT_HTTPS_PORT=${MGMT_HTTPS_PORT:-"8443"}
LOG_LEVEL=${LOG_LEVEL:-"info"}
LOG_FORMAT=${LOG_FORMAT:-"text"}
RATE_LIMIT=${RATE_LIMIT:-"100"}
ENABLE_CAPTCHA=${ENABLE_CAPTCHA:-"true"}

# Display configuration
echo "Configuration:"
echo "  ACME Email: $ACME_EMAIL"
echo "  Domain HTTP Port: $DOMAIN_HTTP_PORT"
echo "  Domain HTTPS Port: $DOMAIN_HTTPS_PORT"
echo "  Management HTTP Port: $MGMT_HTTP_PORT"
echo "  Management HTTPS Port: $MGMT_HTTPS_PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Log Format: $LOG_FORMAT"
echo "  Rate Limit: $RATE_LIMIT req/min"
echo "  Captcha Protection: $ENABLE_CAPTCHA"
echo ""

# Check if running as root for privileged ports
if [[ $DOMAIN_HTTP_PORT -lt 1024 || $DOMAIN_HTTPS_PORT -lt 1024 ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "Warning: Binding to privileged ports (< 1024) requires root privileges."
        echo "Consider using setcap or running with sudo:"
        echo "  sudo setcap 'cap_net_bind_service=+ep' ./proxy-server"
        echo "  OR"
        echo "  sudo $0 $*"
        echo ""
        exit 1
    fi
fi

# Build the binary if it doesn't exist or if source files are newer
if [ ! -f "proxy-server" ] || [ "main.go" -nt "proxy-server" ]; then
    echo "Building proxy server..."
    go build -o proxy-server
    echo "Build complete."
    echo ""
fi

# Set environment variables
export ACME_EMAIL="$ACME_EMAIL"
export DOMAIN_HTTP_PORT="$DOMAIN_HTTP_PORT"
export DOMAIN_HTTPS_PORT="$DOMAIN_HTTPS_PORT"
export MGMT_HTTP_PORT="$MGMT_HTTP_PORT"
export MGMT_HTTPS_PORT="$MGMT_HTTPS_PORT"
export LOG_LEVEL="$LOG_LEVEL"
export LOG_FORMAT="$LOG_FORMAT"
export RATE_LIMIT="$RATE_LIMIT"
export ENABLE_CAPTCHA="$ENABLE_CAPTCHA"

# Check if we should use setcap instead of sudo
if command -v setcap >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
    echo "Setting capabilities for binding to privileged ports..."
    setcap 'cap_net_bind_service=+ep' ./proxy-server
    echo "Capabilities set. You can now run without sudo."
    echo ""
fi

# Start the server
echo "Starting WAF Reverse Proxy..."
echo "Domain traffic: ports $DOMAIN_HTTP_PORT (HTTP) and $DOMAIN_HTTPS_PORT (HTTPS)"
echo "Management interface: ports $MGMT_HTTP_PORT (HTTP) and $MGMT_HTTPS_PORT (HTTPS)"
echo "Web UI available at http://localhost:$MGMT_HTTP_PORT/"
echo "Health check available at http://localhost:$MGMT_HTTP_PORT/health"
echo ""

if [[ $EUID -eq 0 ]]; then
    # Running as root, use exec to replace the shell process
    exec ./proxy-server
else
    # Not root, just run the server
    ./proxy-server
fi
