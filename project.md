# Project: Multi-Domain Self-Hosted Reverse Proxy + Analytics + Anti-Bot Dashboard

## Overview

This project is a **self-hosted reverse proxy manager** that hides origin server IPs while providing:

- **Analytics dashboard** for multiple domains
- **IP enrichment** using findip.net API (with caching)
- **Anti-bot system** based on visitor IP metadata
- **Domain management in the Web UI**

It runs on **Linux/Ubuntu servers**, fully Dockerized, and installs with a single `install.sh`.

---

## Goals

- Manage **multiple domains** from a single dashboard:
  - Add/remove domains via Web UI
  - Configure origin servers per domain
  - Apply custom anti-bot rules per domain
- Hide all origin IPs behind the proxy
- Collect request logs per domain
- Enrich visitor IPs using findip.net
- Provide dashboard insights grouped by domain

---

## Tech Stack

- **Reverse Proxy:** Caddy
  - Dynamic configuration for multiple domains
  - JSON logging per domain
- **Backend / API:** Go service
  - Domain + origin management (CRUD)
  - Stores domain configs in SQLite
  - Parses proxy logs → enriches with findip.net
  - Applies anti-bot rules
  - Exposes API (`/api/domains`, `/api/logs`, `/api/stats`, `/api/bots`)
- **Database:** SQLite
  - Tables: domains, requests, ip_cache, rules
- **Dashboard:** Next.js + Tailwind + shadcn/ui
  - Domain management (list, add, delete)
  - Domain selector for analytics
  - Charts, tables, and anti-bot reports
- **Deployment:** Docker Compose
- **Installer:** Bash (`install.sh`)

---

## Architecture

### Flow

1. Admin adds a **domain + origin server** in the Web UI
2. Backend updates **Caddy config** for that domain (reverse proxy → origin)
3. Visitor requests → Proxy logs → Logger service → DB
4. Logger:
   - Extracts IP + domain
   - Checks cache or calls `findip.net`
   - Saves request with enrichment + anti-bot decision
5. Dashboard:
   - Filter by domain
   - Show analytics, requests, and anti-bot summary

---

## Features

- **Domain management (via UI):**
  - Add/remove domains
  - Set origin IP/hostname
  - Apply per-domain anti-bot rules
- **Analytics (per domain):**
  - Requests by country
  - Requests timeline
  - Visitor logs (IP, geo, ASN, ISP, decision)
- **Anti-bot:**
  - Rules per domain (ASN block, country allowlist, ISP block, user_type filter)
  - Block or allow decisions logged
- **UI:**
  - Domain selector
  - Tables and charts with shadcn components
- **System:**
  - Cached IP lookups
  - Dockerized deployment
  - Installable via `install.sh`

---

## Database Schema (simplified)

- `domains` → id, name, origin_url, created_at
- `requests` → id, domain_id, ip, path, ua, country, isp, org, asn, user_type, decision, timestamp
- `ip_cache` → ip, country, isp, org, asn, user_type, last_checked
- `rules` → id, domain_id, type (allow/deny), field (country/asn/isp/user_type), value

---

## Anti-Bot Logic

- Domain-specific rule sets
- Example:
  - Block `user_type = hosting`
  - Block `asn = 12345`
  - Allow only `country in [DE, US, FR]`

---

## Future Extensions

- UI-based editing of anti-bot rules
- Per-domain TLS certificate management
- Export logs per domain
- Role-based admin access
- WebSocket live traffic feed

---

## Notes for AI Prompting

When asking AI to generate code/configs:

- Specify which component (proxy, backend, dashboard, installer).
- Always support **multiple domains**.
- Store domain configs in DB and reflect changes in proxy automatically.
- API endpoints should include domain context.
- Dashboard should filter/group analytics by domain.
