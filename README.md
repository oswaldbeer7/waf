# WAF - Multi-Domain Self-Hosted Reverse Proxy + Analytics + Anti-Bot Dashboard

A production-ready, self-hosted reverse proxy solution that hides origin server IPs while providing comprehensive analytics and anti-bot protection across multiple domains.

## Features

### 🌐 Multi-Domain Management

- Add/remove domains through an intuitive web interface
- Dynamic Caddy configuration updates
- Hide all origin server IPs behind the proxy

### 📊 Analytics Dashboard

- Real-time request analytics per domain
- Geographic visitor insights (country, ISP, ASN)
- Request timeline and trends
- Interactive charts and visualizations

### 🛡️ Anti-Bot Protection

- Domain-specific bot rules
- IP enrichment using findip.net API
- Configurable allow/deny rules based on:
  - Country
  - ASN (Autonomous System Number)
  - ISP (Internet Service Provider)
  - User type (hosting, commercial, etc.)

### 🔧 Production Ready

- Fully Dockerized deployment
- SQLite database with caching
- Auto-updates with Watchtower
- Health checks and monitoring
- Single-command installation

## Quick Start

### Installation Methods

#### Method 1: One-Line Installation (Easiest)

This method automatically installs all dependencies and sets up the complete system:

```bash
curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash
```

#### Method 2: Complete Setup Script

Installs all system dependencies (Docker, Node.js, Go, etc.) then sets up WAF:

```bash
git clone https://github.com/oswaldbeer7/waf.git
cd waf
chmod +x setup.sh
./setup.sh
```

#### Method 3: Manual Installation

If you already have Docker and dependencies installed:

```bash
git clone https://github.com/oswaldbeer7/waf.git
cd waf
chmod +x install.sh
./install.sh
```

### 2. One-Line Installation (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/oswaldbeer7/waf/main/install-from-github.sh | bash
```

### 3. Manual Installation (Alternative)

```bash
git clone https://github.com/oswaldbeer7/waf.git
cd waf
chmod +x install.sh setup.sh
./install.sh
```

### 4. Complete Setup (Installs All Dependencies)

```bash
chmod +x setup.sh
./setup.sh
```

### 5. Validate Installation

Before building or deploying, validate that all files are present:

```bash
chmod +x validate-build.sh
./validate-build.sh
```

### 6. Access the Dashboard

- **Dashboard**: http://[SERVER_IP]:3000
- **API**: http://[SERVER_IP]:8080
- **Proxy**: http://[SERVER_IP] (for configured domains)

### 7. Configure Your First Domain

1. Open the dashboard at http://[SERVER_IP]:3000
2. Navigate to the "Domains" section
3. Click "Add Domain"
4. Enter your domain name (e.g., `example.com`)
5. Enter your origin server URL (e.g., `http://your-server:8080`)
6. Click "Create Domain"

### 8. Set Up Anti-Bot Rules (Optional)

1. Go to the "Anti-Bot Rules" section
2. Select your domain
3. Add rules to allow or deny traffic based on criteria

## Architecture

```
Internet → Caddy Proxy → Origin Servers
              ↓
        Request Logging → Backend API → Database
              ↓
        IP Enrichment → findip.net API (cached)
              ↓
        Anti-Bot Rules → Decision (allow/block)
              ↓
        Dashboard ← Analytics & Reports
```

### Services

- **Caddy**: Reverse proxy with dynamic configuration
- **Backend**: Go service managing domains, logs, and rules
- **Dashboard**: Next.js web interface with shadcn/ui
- **Database**: SQLite with request logs and configurations
- **Watchtower**: Automatic container updates

## Configuration

### Environment Variables

Edit the `.env` file to customize:

```env
# Database
DB_PATH=/app/data/waf.db

# API Configuration
CADDY_ADMIN_API=http://caddy:2019
NEXT_PUBLIC_API_URL=http://localhost:8080

# Note: The installation scripts will automatically detect your server IP
# and display the correct URLs during installation

# Security (Change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123

# Optional
WATCHTOWER_ENABLED=true
LOG_LEVEL=info
```

### Domain Configuration

Domains are configured through the web interface:

- **Domain Name**: The public domain (e.g., `example.com`)
- **Origin URL**: Your backend server (e.g., `http://192.168.1.100:8080`)

### Anti-Bot Rules

Create rules to control traffic:

- **Allow/Deny**: Choose whether to allow or block matching traffic
- **Field**: Country, ASN, ISP, or User Type
- **Value**: Specific value to match against

Example Rules:

- Deny traffic from hosting providers
- Allow only specific countries
- Block known bot ASNs

## API Endpoints

### Domains

- `GET /api/domains` - List all domains
- `POST /api/domains` - Create new domain
- `PUT /api/domains/{id}` - Update domain
- `DELETE /api/domains/{id}` - Delete domain

### Analytics

- `GET /api/stats` - Overall statistics
- `GET /api/stats/{domain_id}` - Domain-specific stats
- `GET /api/logs` - Recent request logs

### Anti-Bot Rules

- `GET /api/bots/rules?domain_id={id}` - Get rules for domain
- `POST /api/bots/rules` - Create new rule
- `PUT /api/bots/rules/{id}` - Update rule
- `DELETE /api/bots/rules/{id}` - Delete rule

## Security Considerations

### Production Deployment

1. **Change Default Credentials**

   ```bash
   # Edit .env file
   ADMIN_USERNAME=your_secure_username
   ADMIN_PASSWORD=your_strong_password
   ```

2. **Enable SSL/TLS**

   ```env
   # Add to .env
   SSL_CERT_PATH=/path/to/certificate.pem
   SSL_KEY_PATH=/path/to/private.key
   ```

3. **Firewall Configuration**

   ```bash
   sudo ufw allow 80
   sudo ufw allow 443
   sudo ufw allow 3000  # Dashboard (restrict to internal network)
   ```

4. **Reverse Proxy Setup**
   - Use nginx or another reverse proxy in front of the WAF
   - Restrict dashboard access to internal networks
   - Enable rate limiting

### Monitoring

- Check logs: `docker-compose logs -f`
- Database location: `./backend/data/waf.db`
- Caddy logs: `./caddy/logs/`

## Troubleshooting

### Common Issues

1. **Services not starting**

   ```bash
   docker-compose logs
   docker-compose down && docker-compose up -d
   ```

2. **Dashboard not accessible**

   - Check if port 3000 is in use
   - Verify NEXT_PUBLIC_API_URL in .env
   - Check if the server IP is correctly detected by the installation scripts

3. **Domains not working**

   - Check domain configuration in dashboard
   - Verify origin server is accessible from WAF container
   - Check Caddy logs: `docker-compose logs caddy`

4. **IP enrichment not working**
   - Verify internet connectivity
   - Check findip.net API rate limits
   - Review cached data in database

### Debug Commands

```bash
# View all logs
docker-compose logs -f

# Restart specific service
docker-compose restart backend

# Check service health
curl http://localhost:8080/api/health
curl http://localhost:3000/api/health

# Database inspection
docker-compose exec backend sqlite3 /app/data/waf.db ".tables"
```

## Development

### Local Development

1. **Backend Development**

   ```bash
   cd backend
   go run main.go handlers.go database.go
   ```

2. **Dashboard Development**

   ```bash
   cd dashboard
   npm install
   npm run dev
   ```

3. **Database Schema**
   - Tables: domains, requests, ip_cache, rules
   - Located: `./backend/database.go`

### Building from Source

```bash
# Build all images
docker-compose build --no-cache

# Run tests (when implemented)
go test ./backend/...
npm test
```

## Backup and Recovery

### Creating Backups

```bash
# Stop services
./stop.sh

# Backup data
cp -r ./backend/data ./backup/
cp -r ./caddy/data ./backup/
cp ./caddy/Caddyfile ./backup/

# Restart services
./install.sh
```

### Restoring from Backup

```bash
# Stop services
./stop.sh

# Restore data
cp -r ./backup/data ./backend/
cp -r ./backup/caddy_data ./caddy/
cp ./backup/Caddyfile ./caddy/

# Restart services
./install.sh
```

## Support

- **Documentation**: Check this README
- **Issues**: Open GitHub issues with logs
- **Logs**: Include relevant docker-compose logs

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**Note**: This is a production-ready system. Always test in a staging environment before deploying to production. Regularly backup your data and monitor system health.
