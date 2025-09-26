#!/bin/bash

# One-liner WAF installation from GitHub
# Usage: curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash

set -e

REPO_URL="https://raw.githubusercontent.com/oswaldbeer7/waf/main/setup.sh"

echo "=========================================="
echo "WAF One-Line Installation"
echo "=========================================="
echo
echo "Installing WAF (Web Application Firewall)..."
echo "This will install all dependencies and set up the complete system."
 
 
echo "Downloading and running setup script..."

# Download and execute the setup script
bash <(curl -fsSL "$REPO_URL")
