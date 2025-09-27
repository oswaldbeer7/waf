# WAF Reverse Proxy

A production-ready, enterprise-grade reverse proxy server with advanced security features, automatic SSL certificate management, and comprehensive monitoring capabilities.

## 🚀 Key Features

- **🔄 Reverse Proxy**: High-performance routing from configured domains to backend servers
- **🛡️ Advanced Security**: Multi-layer protection with rate limiting, security headers, and captcha
- **🔐 Automatic SSL**: Seamless Let's Encrypt certificate generation with HTTP-01 challenges
- **🔀 Smart Routing**: HTTP to HTTPS automatic redirects with certificate-aware routing
- **🌐 Web Management**: Modern, responsive web interface for domain and SSL management
- **📊 Health Monitoring**: Built-in health checks and uptime tracking
- **⚡ Performance**: Optimized with connection pooling and timeout management
- **🔧 Flexible Configuration**: Environment-based configuration with extensive customization options
- **📝 Structured Logging**: JSON/text logging with configurable levels for production debugging

## API Endpoints

### GET /api/domains

Returns a list of all configured domains.

**Example Response:**

```json
[
  {
    "name": "example.com",
    "backend_url": "http://192.168.1.100:8080",
    "enabled": true
  }
]
```

### POST /api/domains

Adds a new domain configuration.

**Request Body:**

```json
{
  "name": "example.com",
  "backend_url": "http://192.168.1.100:8080",
  "enabled": true
}
```

**Response:** Returns the created domain object with status 201.

### DELETE /api/domains/{name}

Removes a domain configuration.

**Response:** Status 204 (No Content)

## How It Works

1. **Domain Resolution**: The proxy uses the HTTP Host header to determine which backend to route to
2. **Captcha Check**: First-time visitors see a captcha page requiring them to click "OK - I'm Human"
3. **Cookie-Based Session**: After passing captcha, users get a cookie that lasts 1 hour
4. **Proxy Pass-Through**: Subsequent requests are proxied to the configured backend

## 🚀 Quick Start

### Using the Startup Script (Recommended)

```bash
# Basic usage with defaults
sudo ./start.sh

# Advanced configuration
sudo ./start.sh --email admin@example.com --log-level debug --rate-limit 50

# Custom ports (for non-privileged ports)
./start.sh --domain-port 8080 --domain-https-port 8443 --mgmt-port 3000 --mgmt-https-port 3001

# Get help
./start.sh --help
```

### Manual Configuration

```bash
# Set environment variables
export ACME_EMAIL="admin@example.com"
export DOMAIN_HTTP_PORT="80"
export DOMAIN_HTTPS_PORT="443"
export MGMT_HTTP_PORT="3000"
export MGMT_HTTPS_PORT="8443"
export LOG_LEVEL="info"
export RATE_LIMIT="100"

# Start the server
sudo ./proxy-server
```

### Configuration Options

| Variable            | Default             | Description                             |
| ------------------- | ------------------- | --------------------------------------- |
| `ACME_EMAIL`        | `admin@example.com` | Email for Let's Encrypt registration    |
| `DOMAIN_HTTP_PORT`  | `80`                | HTTP port for domain traffic            |
| `DOMAIN_HTTPS_PORT` | `443`               | HTTPS port for domain traffic           |
| `MGMT_HTTP_PORT`    | `3000`              | HTTP port for management interface      |
| `MGMT_HTTPS_PORT`   | `8443`              | HTTPS port for management interface     |
| `LOG_LEVEL`         | `info`              | Logging level: debug, info, warn, error |
| `LOG_FORMAT`        | `text`              | Log format: text, json                  |
| `RATE_LIMIT`        | `100`               | Requests per minute per IP              |
| `ENABLE_CAPTCHA`    | `true`              | Enable captcha protection               |

2. **Add domains via API:**

   ```bash
   # Use the management interface (port 3000)
   curl -X POST http://localhost:3000/api/domains \
     -H "Content-Type: application/json" \
     -d '{"name": "example.com", "backend_url": "http://your-backend:8080", "enabled": true}'

   # Or use HTTPS management interface
   curl -X POST https://localhost:8443/api/domains \
     -H "Content-Type: application/json" \
     -d '{"name": "example.com", "backend_url": "http://your-backend:8080", "enabled": true}'
   ```

3. **Configure your DNS:**
   Point your domain (e.g., example.com) to your server IP (62.60.176.79)

4. **Test the proxy:**

   ```bash
   # Test domain traffic (goes to ports 80/443)
   curl http://example.com/

   # Or test with your server IP directly
   curl http://62.60.176.79/ -H "Host: example.com"
   ```

5. **Access Web UI:**

   ```bash
   # Management interface for domain configuration
   http://localhost:3000/  # or https://localhost:8443/
   ```

   You should see the captcha page first, then be redirected to your backend

## Web UI

The reverse proxy includes a modern web interface for easy domain management:

- **Access**: Visit the root URL of your proxy server (e.g., `https://your-proxy.com/`)
- **Features**:
  - Add new domains with SSL certificate options
  - Edit existing domain configurations
  - Toggle SSL certificate generation
  - Enable/disable domains
  - Delete domains
  - Real-time status indicators

The web UI uses Tailwind CSS for a clean, responsive design and communicates with the REST API.

## SSL Certificate Generation

The proxy automatically generates Let's Encrypt SSL certificates for domains when they are added with `ssl_enabled: true`. The certificate generation process:

1. **HTTP-01 Challenge**: Uses port 80 to complete the ACME HTTP-01 challenge
2. **Automatic Registration**: Registers with Let's Encrypt using the provided email
3. **Certificate Storage**: Stores certificates in memory for fast retrieval
4. **HTTP to HTTPS Redirect**: Automatically redirects HTTP traffic to HTTPS when SSL certificates are available

### SSL Configuration Options

When adding a domain, you can configure SSL settings:

```json
{
  "name": "example.com",
  "backend_url": "http://your-backend:8080",
  "enabled": true,
  "ssl_enabled": true,
  "auto_ssl": true
}
```

- `ssl_enabled`: Enable/disable SSL for this domain
- `auto_ssl`: Automatically generate Let's Encrypt certificates (default: true)

### Environment Variables

**Domain Traffic Ports:**

- `DOMAIN_HTTP_PORT`: HTTP port for domain traffic (default: 80)
- `DOMAIN_HTTPS_PORT`: HTTPS port for domain traffic (default: 443)

**Management Interface Ports:**

- `HTTP_PORT`: HTTP port for web UI and API (default: 3000)
- `HTTPS_PORT`: HTTPS port for web UI and API (default: 8443)

**Other:**

- `SERVER_IP`: Server IP address to bind to (default: auto-detected)

_Note: Let's Encrypt registration email is hardcoded to `karolinmunaln@gmx.de`_

## Example Domain Configuration

```bash
# Add a domain with SSL enabled (will auto-generate Let's Encrypt certificate)
curl -X POST http://localhost/api/domains \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp.local", "backend_url": "http://localhost:3000", "enabled": true, "ssl_enabled": true}'

# Add a domain that proxies to a remote server with SSL
curl -X POST http://localhost/api/domains \
  -H "Content-Type: application/json" \
  -d '{"name": "api.example.com", "backend_url": "http://192.168.1.50:8080", "enabled": true, "ssl_enabled": true}'
```

## 🔒 Security Features

- **Rate Limiting**: Configurable per-IP request limits (default: 100/minute)
- **Security Headers**: Automatic addition of security headers (HSTS, CSP, X-Frame-Options, etc.)
- **Captcha Protection**: Human verification with configurable session duration
- **TLS Configuration**: Secure TLS 1.2+ with strong cipher suites
- **Graceful Shutdown**: Clean shutdown handling to prevent connection drops
- **Structured Logging**: Comprehensive audit trail with configurable log levels

## ⚠️ Security Notes

- **API Authentication**: The management API has no authentication by default
  - Restrict access using firewalls (e.g., only allow trusted IPs)
  - Consider running management interface on private network
- **SSL Requirements**: For automatic certificate generation, ensure ports 80 and 443 are publicly accessible
- **Privileged Ports**: Ports < 1024 require root privileges or `setcap` capabilities
- **Production Deployment**: Use proper firewall rules and consider containerization

## 🔧 Advanced Configuration

### Custom TLS Cipher Suites

The proxy uses secure defaults, but you can customize TLS cipher suites:

```bash
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
```

### JSON Logging for Production

```bash
export LOG_FORMAT="json"
export LOG_LEVEL="info"
```

### High Security Mode

```bash
export RATE_LIMIT="50"
export ENABLE_CAPTCHA="true"
export LOG_LEVEL="debug"
```

## 🛠️ Troubleshooting

### ACME Challenge Issues

If you encounter "bind: address already in use" errors during SSL certificate generation:

1. **Port Conflicts**: Ensure no other services are running on ports 80 or 443
2. **Check Processes**: Use `sudo lsof -i :80` and `sudo lsof -i :443` to identify conflicts
3. **Alternative Ports**: For testing, use non-privileged ports:
   ```bash
   ./start.sh --domain-port 8080 --domain-https-port 8443
   ```

### TLS Handshake Errors

If you see "no certificate found for domain" errors:

1. **Domain Configuration**: Ensure the domain is properly configured via the API
2. **DNS Propagation**: Wait for DNS changes to propagate
3. **SSL Generation**: Check logs for SSL certificate generation status
4. **On-Demand Generation**: Certificates are generated automatically on first TLS request

### Performance Issues

For high-traffic scenarios:

1. **Increase Rate Limits**: Adjust `RATE_LIMIT` environment variable
2. **Optimize Timeouts**: The proxy uses 30s read/write timeouts by default
3. **Monitor Resources**: Use the `/health` endpoint to monitor system status
4. **Consider Load Balancing**: Deploy multiple instances behind a load balancer

### Common Commands

```bash
# Check if ports are in use
sudo lsof -i :80 :443

# Monitor logs in real-time
tail -f /var/log/syslog | grep proxy-server

# Test domain configuration
curl -H "Host: example.com" http://localhost/

# Check health status
curl http://localhost:3000/health
```
