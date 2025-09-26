# WAF Reverse Proxy

A simple Go-based reverse proxy server with built-in captcha protection and domain management.

## Features

- **Reverse Proxy**: Routes traffic from configured domains to backend servers
- **Captcha Protection**: Shows a simple "OK" button captcha before allowing access
- **Domain Management**: REST API for adding/removing domains without authentication
- **Thread-Safe**: Uses mutex locks for safe concurrent access to domain configurations

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

## Usage

1. **Start the server:**

   ```bash
   # Start on default port 8080
   ./proxy-server

   # Or start on port 80 (requires root/sudo)
   sudo PORT=80 ./proxy-server

   # Or use the startup script
   ./start.sh
   ```

2. **Add domains via API:**

   ```bash
   # If running on port 8080
   curl -X POST http://localhost:8080/api/domains \
     -H "Content-Type: application/json" \
     -d '{"name": "example.com", "backend_url": "http://your-backend:8080", "enabled": true}'

   # If running on port 80
   curl -X POST http://localhost/api/domains \
     -H "Content-Type: application/json" \
     -d '{"name": "example.com", "backend_url": "http://your-backend:8080", "enabled": true}'
   ```

3. **Configure your DNS:**
   Point your domain (e.g., example.com) to the server running this proxy

4. **Test the proxy:**

   ```bash
   # If running on port 8080
   curl http://localhost:8080/ -H "Host: example.com"

   # Or visit in browser: http://localhost:8080 (with Host header set to example.com)
   ```

   You should see the captcha page first, then be redirected to your backend

## Example Domain Configuration

```bash
# Add a domain that proxies to a local service
curl -X POST http://localhost:8080/api/domains \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp.local", "backend_url": "http://localhost:3000", "enabled": true}'

# Add a domain that proxies to a remote server
curl -X POST http://localhost:8080/api/domains \
  -H "Content-Type: application/json" \
  -d '{"name": "api.example.com", "backend_url": "http://192.168.1.50:8080", "enabled": true}'
```

## Security Notes

- The API has **no authentication** - make sure to secure access to your chosen port (80 or 8080)
- The captcha cookie lasts for 1 hour and is HTTP-only
- Consider using a firewall to restrict API access to trusted IPs only
- For production use on port 80, run with `sudo PORT=80 ./proxy-server`
