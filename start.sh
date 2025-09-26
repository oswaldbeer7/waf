#!/bin/bash

# Simple startup script for the WAF Reverse Proxy

echo "Starting WAF Reverse Proxy..."
echo "Server will listen on port 80"
echo "API endpoints available at http://localhost/api/domains"
echo ""

# Build the binary if it doesn't exist or if source files are newer
if [ ! -f "proxy-server" ] || [ "main.go" -nt "proxy-server" ]; then
    echo "Building proxy server..."
    go build -o proxy-server
fi

# Start the server
./proxy-server
