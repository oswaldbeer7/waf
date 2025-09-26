package main

import (
    "database/sql"
    "fmt"
    "log"
    "time"

    _ "modernc.org/sqlite"
)

type Database struct {
    *sql.DB
}

func InitializeDB(dbPath string) (*Database, error) {
    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %v", err)
    }

    // Test the connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %v", err)
    }

    database := &Database{db}

    // Create tables
    if err := database.createTables(); err != nil {
        return nil, fmt.Errorf("failed to create tables: %v", err)
    }

    log.Println("Database initialized successfully")
    return database, nil
}

func (db *Database) createTables() error {
    // Domains table
    domainsTable := `
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        origin_url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`

    // Requests table
    requestsTable := `
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        path TEXT NOT NULL,
        user_agent TEXT,
        country TEXT,
        isp TEXT,
        org TEXT,
        asn TEXT,
        user_type TEXT,
        decision TEXT DEFAULT 'allow',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains (id)
    )`

    // IP cache table
    ipCacheTable := `
    CREATE TABLE IF NOT EXISTS ip_cache (
        ip TEXT PRIMARY KEY,
        country TEXT,
        isp TEXT,
        org TEXT,
        asn TEXT,
        user_type TEXT,
        last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
    )`

    // Bot rules table
    botRulesTable := `
    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('allow', 'deny')),
        field TEXT NOT NULL CHECK (field IN ('country', 'asn', 'isp', 'user_type')),
        value TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains (id),
        UNIQUE(domain_id, field, value)
    )`

    // Create indexes for better performance
    indexes := `
    CREATE INDEX IF NOT EXISTS idx_requests_domain_id ON requests(domain_id);
    CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
    CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip);
    CREATE INDEX IF NOT EXISTS idx_requests_decision ON requests(decision);
    CREATE INDEX IF NOT EXISTS idx_ip_cache_last_checked ON ip_cache(last_checked);
    CREATE INDEX IF NOT EXISTS idx_rules_domain_id ON rules(domain_id)`

    tables := []string{domainsTable, requestsTable, ipCacheTable, botRulesTable, indexes}

    for _, table := range tables {
        if _, err := db.Exec(table); err != nil {
            return fmt.Errorf("failed to create table: %v", err)
        }
    }

    return nil
}

// Domain operations
func (db *Database) CreateDomain(name, originURL string) (*Domain, error) {
    query := `INSERT INTO domains (name, origin_url) VALUES (?, ?)`
    result, err := db.Exec(query, name, originURL)
    if err != nil {
        return nil, err
    }

    id, err := result.LastInsertId()
    if err != nil {
        return nil, err
    }

    return &Domain{
        ID:        int(id),
        Name:      name,
        OriginURL: originURL,
        CreatedAt: time.Now().Format(time.RFC3339),
    }, nil
}

func (db *Database) GetDomains() ([]Domain, error) {
    query := `SELECT id, name, origin_url, created_at FROM domains ORDER BY created_at DESC`
    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var domains []Domain
    for rows.Next() {
        var domain Domain
        err := rows.Scan(&domain.ID, &domain.Name, &domain.OriginURL, &domain.CreatedAt)
        if err != nil {
            return nil, err
        }
        domains = append(domains, domain)
    }

    return domains, nil
}

func (db *Database) GetDomainByID(id int) (*Domain, error) {
    query := `SELECT id, name, origin_url, created_at FROM domains WHERE id = ?`
    var domain Domain
    err := db.QueryRow(query, id).Scan(&domain.ID, &domain.Name, &domain.OriginURL, &domain.CreatedAt)
    if err != nil {
        return nil, err
    }
    return &domain, nil
}

func (db *Database) UpdateDomain(id int, name, originURL string) error {
    query := `UPDATE domains SET name = ?, origin_url = ? WHERE id = ?`
    _, err := db.Exec(query, name, originURL, id)
    return err
}

func (db *Database) DeleteDomain(id int) error {
    query := `DELETE FROM domains WHERE id = ?`
    _, err := db.Exec(query, id)
    return err
}

// Request operations
func (db *Database) LogRequest(domainID int, ip, path, userAgent, country, isp, org, asn, userType, decision string) error {
    query := `INSERT INTO requests (domain_id, ip, path, user_agent, country, isp, org, asn, user_type, decision)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    _, err := db.Exec(query, domainID, ip, path, userAgent, country, isp, org, asn, userType, decision)
    return err
}

func (db *Database) GetRequests(limit int) ([]RequestLog, error) {
    query := `SELECT r.id, r.domain_id, r.ip, r.path, r.user_agent, r.country, r.isp, r.org, r.asn, r.user_type, r.decision, r.timestamp
              FROM requests r
              JOIN domains d ON r.domain_id = d.id
              ORDER BY r.timestamp DESC LIMIT ?`
    return db.getRequestLogs(query, limit)
}

func (db *Database) GetDomainRequests(domainID, limit int) ([]RequestLog, error) {
    query := `SELECT id, domain_id, ip, path, user_agent, country, isp, org, asn, user_type, decision, timestamp
              FROM requests WHERE domain_id = ? ORDER BY timestamp DESC LIMIT ?`
    return db.getRequestLogs(query, domainID, limit)
}

func (db *Database) getRequestLogs(query string, args ...interface{}) ([]RequestLog, error) {
    rows, err := db.Query(query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var logs []RequestLog
    for rows.Next() {
        var log RequestLog
        err := rows.Scan(&log.ID, &log.DomainID, &log.IP, &log.Path, &log.UserAgent,
                        &log.Country, &log.ISP, &log.Org, &log.ASN, &log.UserType,
                        &log.Decision, &log.Timestamp)
        if err != nil {
            return nil, err
        }
        logs = append(logs, log)
    }
    return logs, nil
}

// IP cache operations
func (db *Database) GetIPInfo(ip string) (*IPInfo, error) {
    query := `SELECT ip, country, isp, org, asn, user_type FROM ip_cache WHERE ip = ?`
    var info IPInfo
    err := db.QueryRow(query, ip).Scan(&info.IP, &info.Country, &info.ISP, &info.Org, &info.ASN, &info.UserType)
    if err != nil {
        return nil, err
    }
    return &info, nil
}

func (db *Database) CacheIPInfo(info *IPInfo) error {
    query := `INSERT OR REPLACE INTO ip_cache (ip, country, isp, org, asn, user_type, last_checked)
              VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
    _, err := db.Exec(query, info.IP, info.Country, info.ISP, info.Org, info.ASN, info.UserType)
    return err
}

func (db *Database) GetExpiredIPCache(olderThan time.Duration) ([]string, error) {
    query := `SELECT ip FROM ip_cache WHERE last_checked < datetime('now', ?)`
    cutoff := fmt.Sprintf("-%d seconds", int(olderThan.Seconds()))
    rows, err := db.Query(query, cutoff)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var ips []string
    for rows.Next() {
        var ip string
        if err := rows.Scan(&ip); err != nil {
            return nil, err
        }
        ips = append(ips, ip)
    }
    return ips, nil
}

// Bot rules operations
func (db *Database) GetBotRules(domainID int) ([]BotRule, error) {
    query := `SELECT id, domain_id, type, field, value FROM rules WHERE domain_id = ? ORDER BY created_at DESC`
    rows, err := db.Query(query, domainID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var rules []BotRule
    for rows.Next() {
        var rule BotRule
        err := rows.Scan(&rule.ID, &rule.DomainID, &rule.Type, &rule.Field, &rule.Value)
        if err != nil {
            return nil, err
        }
        rules = append(rules, rule)
    }
    return rules, nil
}

func (db *Database) CreateBotRule(domainID int, ruleType, field, value string) (*BotRule, error) {
    query := `INSERT INTO rules (domain_id, type, field, value) VALUES (?, ?, ?, ?)`
    result, err := db.Exec(query, domainID, ruleType, field, value)
    if err != nil {
        return nil, err
    }

    id, err := result.LastInsertId()
    if err != nil {
        return nil, err
    }

    return &BotRule{
        ID:       int(id),
        DomainID: domainID,
        Type:     ruleType,
        Field:    field,
        Value:    value,
    }, nil
}

func (db *Database) DeleteBotRule(id int) error {
    query := `DELETE FROM rules WHERE id = ?`
    _, err := db.Exec(query, id)
    return err
}

// Statistics operations
func (db *Database) GetStats(domainID int) (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Total requests
    var totalRequests int
    query := `SELECT COUNT(*) FROM requests`
    if domainID > 0 {
        query += ` WHERE domain_id = ?`
        err := db.QueryRow(query, domainID).Scan(&totalRequests)
        if err != nil {
            return nil, err
        }
    } else {
        err := db.QueryRow(query).Scan(&totalRequests)
        if err != nil {
            return nil, err
        }
    }
    stats["total_requests"] = totalRequests

    // Requests by country
    countryStats := make(map[string]int)
    query = `SELECT country, COUNT(*) as count FROM requests WHERE country IS NOT NULL`
    if domainID > 0 {
        query += ` AND domain_id = ?`
    }
    query += ` GROUP BY country ORDER BY count DESC LIMIT 10`

    rows, err := db.Query(query, domainID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var country string
        var count int
        if err := rows.Scan(&country, &count); err != nil {
            return nil, err
        }
        countryStats[country] = count
    }
    stats["requests_by_country"] = countryStats

    // Blocked vs allowed requests
    var blocked, allowed int
    query = `SELECT decision, COUNT(*) FROM requests`
    if domainID > 0 {
        query += ` WHERE domain_id = ?`
    }
    query += ` GROUP BY decision`

    rows, err = db.Query(query, domainID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var decision string
        var count int
        if err := rows.Scan(&decision, &count); err != nil {
            return nil, err
        }
        if decision == "block" {
            blocked = count
        } else {
            allowed = count
        }
    }
    stats["blocked_requests"] = blocked
    stats["allowed_requests"] = allowed

    return stats, nil
}
