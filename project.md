# Project: Self-Hosted Reverse Proxy + Analytics + Anti-Bot Dashboard

## Overview

This project is a **self-hosted reverse proxy** that hides an origin server’s IP while providing:

- **Lightweight analytics dashboard**
- **IP metadata enrichment via findip.net API**
- **Anti-bot detection layer** using IP info

It runs fully in **Docker**, with one-command installation via `install.sh`, deployable on **Linux/Ubuntu servers**.

---

## Goals

- Hide the **origin server IP** behind a reverse proxy.
- Collect and store visitor request logs (IP, time, path, headers).
- Enrich IPs using **findip.net API** (with local caching).
- Add basic **anti-bot detection**, e.g.:
  - Flag/block traffic from hosting/VPN providers.
  - Block specific ASNs or ISPs.
  - Whitelist/blacklist countries.
- Provide a **clean modern dashboard** with:
  - Logs + IP enrichment
  - Requests per country
  - Requests per time interval
  - Anti-bot flags (e.g. suspicious, blocked, allowed)

---

## Tech Stack

- **Reverse Proxy:** Caddy (lightweight, auto-HTTPS, JSON logging)
- **Backend / API:** Go service
  - Parses logs from proxy
  - Calls `https://api.findip.net/<IP>?token=...`
  - Extracts: `country`, `isp`, `organization`, `asn`, `user_type`
  - Caches responses (SQLite or in-memory + TTL)
  - Stores requests in SQLite
  - Implements anti-bot rules
  - Exposes REST/GraphQL API (`/api/logs`, `/api/stats`, `/api/bots`)
- **Database:** SQLite (file-based, no dependencies)
- **Dashboard:** Next.js + Tailwind + shadcn/ui + Recharts
- **Deployment:** Docker + Docker Compose
- **Installer:** Bash (`install.sh`)
  - Installs Docker + Compose
  - Clones repo
  - Runs `docker compose up -d`

---

## Architecture

### Flow

1. Visitor → **Caddy proxy** → Origin server
2. Caddy logs → **Go logger service**
3. Logger service:
   - Extracts visitor IP
   - Checks SQLite cache → if missing → calls **findip.net API**
   - Saves IP metadata + request data
   - Runs anti-bot checks:
     - Known hosting/VPN providers?
     - Suspicious ASN/org/ISP?
     - Blocked/allowed country?
   - Stores decision in DB
4. **Dashboard** (Next.js + shadcn) queries API and visualizes:
   - Requests per country
   - Requests timeline
   - Visitor log table (IP, geo, ISP, decision)
   - Anti-bot stats (blocked/allowed)

---

## Features

- Reverse proxy (hide origin IP)
- Log collection (requests, headers, IPs)
- Enrichment:
  - IP → country, ASN, ISP, org, user type (via findip.net)
  - Cached lookups to minimize API calls
- Anti-bot:
  - Flag traffic by rules (country, ASN, ISP, user type)
  - Option to block directly at proxy level (return 403)
- Dashboard:
  - Requests table with enrichment info
  - Charts by country and time
  - Anti-bot summary (suspicious/blocked hits)
- Dockerized deployment
- One-command install script

---

## Deployment

- Run `install.sh`:
  - Installs Docker + Compose
  - Clones repo
  - Runs `docker compose up -d`
- Services:
  - `proxy` → Caddy reverse proxy
  - `logger-api` → Go service (log parser, enrichment, anti-bot, API)
  - `dashboard` → Next.js app with shadcn UI

---

## Anti-Bot Logic (Example)

- Block if `user_type == hosting`
- Block if `isp` or `organization` contains known VPN/Proxy providers
- Block by ASN blacklist (configurable)
- Allow only specific countries (whitelist mode)
- Cache IP decision results in SQLite

---

## Future Extensions

- Admin UI for editing anti-bot rules
- Export logs/stats to CSV/JSON
- Live request feed with WebSocket
- Map view (Leaflet.js + visitor geo coords)
- Multi-origin routing (load balancing)

---

## Notes for AI Prompting

- Specify which component to generate (proxy config, Go service, API routes, dashboard, installer).
- Always respect this **tech stack**.
- Keep it lightweight and Docker-compatible.
- For IP enrichment, use:
  GET https://api.findip.net/
  and cache results locally.
- Only keep these fields: `country`, `isp`, `organization`, `asn`, `user_type`.
