package main

import (
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/gorilla/mux"
    "github.com/go-resty/resty/v2"
)

// Domain handlers
func (app *App) getDomains(w http.ResponseWriter, r *http.Request) {
    domains, err := app.DB.GetDomains()
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get domains")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(domains)
}

func (app *App) createDomain(w http.ResponseWriter, r *http.Request) {
    var domain Domain
    if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if domain.Name == "" || domain.OriginURL == "" {
        http.Error(w, "Name and origin_url are required", http.StatusBadRequest)
        return
    }

    // Validate domain name format
    if !isValidDomain(domain.Name) {
        http.Error(w, "Invalid domain name format", http.StatusBadRequest)
        return
    }

    // Validate origin URL format
    if !isValidURL(domain.OriginURL) {
        http.Error(w, "Invalid origin URL format", http.StatusBadRequest)
        return
    }

    createdDomain, err := app.DB.CreateDomain(domain.Name, domain.OriginURL)
    if err != nil {
        if strings.Contains(err.Error(), "UNIQUE constraint failed") {
            http.Error(w, "Domain already exists", http.StatusConflict)
            return
        }
        app.Logger.WithError(err).Error("Failed to create domain")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Update Caddy configuration
    if err := app.updateCaddyConfig(createdDomain); err != nil {
        app.Logger.WithError(err).Error("Failed to update Caddy configuration")
        // Note: We should probably rollback the domain creation here
        http.Error(w, "Failed to update proxy configuration", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(createdDomain)
}

func (app *App) updateDomain(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid domain ID", http.StatusBadRequest)
        return
    }

    var domain Domain
    if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if domain.Name == "" || domain.OriginURL == "" {
        http.Error(w, "Name and origin_url are required", http.StatusBadRequest)
        return
    }

    if err := app.DB.UpdateDomain(id, domain.Name, domain.OriginURL); err != nil {
        app.Logger.WithError(err).Error("Failed to update domain")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Get updated domain
    updatedDomain, err := app.DB.GetDomainByID(id)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get updated domain")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Update Caddy configuration
    if err := app.updateCaddyConfig(updatedDomain); err != nil {
        app.Logger.WithError(err).Error("Failed to update Caddy configuration")
        http.Error(w, "Failed to update proxy configuration", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(updatedDomain)
}

func (app *App) deleteDomain(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid domain ID", http.StatusBadRequest)
        return
    }

    // Get domain before deletion for Caddy config update
    domain, err := app.DB.GetDomainByID(id)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get domain for deletion")
        http.Error(w, "Domain not found", http.StatusNotFound)
        return
    }

    if err := app.DB.DeleteDomain(id); err != nil {
        app.Logger.WithError(err).Error("Failed to delete domain")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Remove from Caddy configuration
    if err := app.removeCaddyConfig(domain); err != nil {
        app.Logger.WithError(err).Error("Failed to update Caddy configuration after domain deletion")
        // Note: Domain is already deleted from DB, but Caddy config might still have it
    }

    w.WriteHeader(http.StatusNoContent)
}

// Request log handlers
func (app *App) getLogs(w http.ResponseWriter, r *http.Request) {
    limitStr := r.URL.Query().Get("limit")
    limit := 100 // default
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
            limit = parsedLimit
        }
    }

    logs, err := app.DB.GetRequests(limit)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get request logs")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(logs)
}

func (app *App) getDomainLogs(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    domainID, err := strconv.Atoi(vars["domain_id"])
    if err != nil {
        http.Error(w, "Invalid domain ID", http.StatusBadRequest)
        return
    }

    limitStr := r.URL.Query().Get("limit")
    limit := 100 // default
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
            limit = parsedLimit
        }
    }

    logs, err := app.DB.GetDomainRequests(domainID, limit)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get domain request logs")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(logs)
}

// Statistics handlers
func (app *App) getStats(w http.ResponseWriter, r *http.Request) {
    stats, err := app.DB.GetStats(0) // 0 means all domains
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get statistics")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(stats)
}

func (app *App) getDomainStats(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    domainID, err := strconv.Atoi(vars["domain_id"])
    if err != nil {
        http.Error(w, "Invalid domain ID", http.StatusBadRequest)
        return
    }

    stats, err := app.DB.GetStats(domainID)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get domain statistics")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(stats)
}

// Bot rules handlers
func (app *App) getBotRules(w http.ResponseWriter, r *http.Request) {
    domainIDStr := r.URL.Query().Get("domain_id")
    if domainIDStr == "" {
        http.Error(w, "domain_id parameter is required", http.StatusBadRequest)
        return
    }

    domainID, err := strconv.Atoi(domainIDStr)
    if err != nil {
        http.Error(w, "Invalid domain_id", http.StatusBadRequest)
        return
    }

    rules, err := app.DB.GetBotRules(domainID)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get bot rules")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(rules)
}

func (app *App) createBotRule(w http.ResponseWriter, r *http.Request) {
    var rule BotRule
    if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if rule.DomainID == 0 || rule.Type == "" || rule.Field == "" || rule.Value == "" {
        http.Error(w, "domain_id, type, field, and value are required", http.StatusBadRequest)
        return
    }

    if rule.Type != "allow" && rule.Type != "deny" {
        http.Error(w, "Type must be 'allow' or 'deny'", http.StatusBadRequest)
        return
    }

    validFields := []string{"country", "asn", "isp", "user_type"}
    if !contains(validFields, rule.Field) {
        http.Error(w, "Field must be one of: country, asn, isp, user_type", http.StatusBadRequest)
        return
    }

    createdRule, err := app.DB.CreateBotRule(rule.DomainID, rule.Type, rule.Field, rule.Value)
    if err != nil {
        if strings.Contains(err.Error(), "UNIQUE constraint failed") {
            http.Error(w, "Rule already exists for this domain and field", http.StatusConflict)
            return
        }
        app.Logger.WithError(err).Error("Failed to create bot rule")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(createdRule)
}

func (app *App) updateBotRule(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid rule ID", http.StatusBadRequest)
        return
    }

    var rule BotRule
    if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if rule.Type != "allow" && rule.Type != "deny" {
        http.Error(w, "Type must be 'allow' or 'deny'", http.StatusBadRequest)
        return
    }

    validFields := []string{"country", "asn", "isp", "user_type"}
    if !contains(validFields, rule.Field) {
        http.Error(w, "Field must be one of: country, asn, isp, user_type", http.StatusBadRequest)
        return
    }

    // Delete old rule and create new one (since we can't update with unique constraint)
    if err := app.DB.DeleteBotRule(id); err != nil {
        app.Logger.WithError(err).Error("Failed to delete old bot rule")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    createdRule, err := app.DB.CreateBotRule(rule.DomainID, rule.Type, rule.Field, rule.Value)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to create updated bot rule")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(createdRule)
}

func (app *App) deleteBotRule(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid rule ID", http.StatusBadRequest)
        return
    }

    if err := app.DB.DeleteBotRule(id); err != nil {
        app.Logger.WithError(err).Error("Failed to delete bot rule")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// Log ingestion handler (called by Caddy)
func (app *App) ingestLog(w http.ResponseWriter, r *http.Request) {
    var logData map[string]interface{}
    if err := json.NewDecoder(r.Body).Decode(&logData); err != nil {
        app.Logger.WithError(err).Error("Failed to decode log data")
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Extract data from Caddy log
    domain := getStringFromMap(logData, "domain")
    ip := getStringFromMap(logData, "ip")
    path := getStringFromMap(logData, "path")
    userAgent := getStringFromMap(logData, "user_agent")

    if domain == "" || ip == "" {
        app.Logger.Error("Missing required fields in log data")
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Get domain ID
    domainID, err := app.getDomainIDByName(domain)
    if err != nil {
        app.Logger.WithError(err).WithField("domain", domain).Error("Failed to get domain ID")
        http.Error(w, "Domain not found", http.StatusNotFound)
        return
    }

    // Enrich IP data
    ipInfo, err := app.enrichIPData(ip)
    if err != nil {
        app.Logger.WithError(err).WithField("ip", ip).Warn("Failed to enrich IP data")
        // Continue with empty enrichment data
        ipInfo = &IPInfo{IP: ip}
    }

    // Apply bot rules
    decision := app.applyBotRules(domainID, ipInfo)

    // Log the request
    if err := app.DB.LogRequest(domainID, ip, path, userAgent,
        ipInfo.Country, ipInfo.ISP, ipInfo.Org, ipInfo.ASN, ipInfo.UserType, decision); err != nil {
        app.Logger.WithError(err).Error("Failed to log request")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Log the decision
    app.Logger.WithFields(map[string]interface{}{
        "domain":   domain,
        "ip":       ip,
        "path":     path,
        "decision": decision,
        "country":  ipInfo.Country,
        "user_type": ipInfo.UserType,
    }).Info("Request processed")

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

// Helper functions
func (app *App) updateCaddyConfig(domain *Domain) error {
    // Create Caddy configuration for the domain
    config := map[string]interface{}{
        "@name": map[string]interface{}{
            "host": domain.Name,
        },
        "handle": []map[string]interface{}{
            {
                "handler": "reverse_proxy",
                "upstreams": []map[string]interface{}{
                    {
                        "dial": domain.OriginURL,
                    },
                },
            },
            {
                "handler": "request_body",
                "name": "body",
            },
            {
                "handler": "copy_response_headers",
                "headers": map[string]string{
                    "Server": "Caddy",
                },
            },
        },
        "handle_errors": []map[string]interface{}{
            {
                "handler": "static_response",
                "status_code": 500,
                "body": "Internal Server Error",
            },
        },
    }

    // Load current Caddy config
    currentConfig, err := app.loadCaddyConfig()
    if err != nil {
        return err
    }

    // Add new route
    if currentConfig["http"] == nil {
        currentConfig["http"] = map[string]interface{}{}
    }

    httpConfig := currentConfig["http"].(map[string]interface{})
    if httpConfig["routes"] == nil {
        httpConfig["routes"] = []interface{}{}
    }

    routes := httpConfig["routes"].([]interface{})
    routes = append(routes, config)
    httpConfig["routes"] = routes

    // Save updated config
    return app.saveCaddyConfig(currentConfig)
}

func (app *App) removeCaddyConfig(domain *Domain) error {
    // Load current Caddy config
    currentConfig, err := app.loadCaddyConfig()
    if err != nil {
        return err
    }

    if currentConfig["http"] == nil {
        return nil // No routes to remove
    }

    httpConfig := currentConfig["http"].(map[string]interface{})
    if httpConfig["routes"] == nil {
        return nil // No routes to remove
    }

    routes := httpConfig["routes"].([]interface{})
    var newRoutes []interface{}

    // Remove routes for this domain
    for _, route := range routes {
        routeMap := route.(map[string]interface{})
        if nameMatcher, exists := routeMap["@name"]; exists {
            if hostMatcher, ok := nameMatcher.(map[string]interface{}); ok {
                if host, exists := hostMatcher["host"]; exists {
                    if host != domain.Name {
                        newRoutes = append(newRoutes, route)
                    }
                } else {
                    newRoutes = append(newRoutes, route)
                }
            } else {
                newRoutes = append(newRoutes, route)
            }
        } else {
            newRoutes = append(newRoutes, route)
        }
    }

    httpConfig["routes"] = newRoutes

    // Save updated config
    return app.saveCaddyConfig(currentConfig)
}

func (app *App) loadCaddyConfig() (map[string]interface{}, error) {
    client := resty.New()
    resp, err := client.R().Get(app.CaddyAdminAPI + "/config/")
    if err != nil {
        return nil, err
    }

    var config map[string]interface{}
    if err := json.Unmarshal(resp.Body(), &config); err != nil {
        return nil, err
    }

    return config, nil
}

func (app *App) saveCaddyConfig(config map[string]interface{}) error {
    client := resty.New()
    resp, err := client.R().
        SetHeader("Content-Type", "application/json").
        SetBody(config).
        Post(app.CaddyAdminAPI + "/load")
    if err != nil {
        return err
    }

    if resp.StatusCode() != 200 {
        return http.ErrNotSupported
    }

    return nil
}

func (app *App) getDomainIDByName(domainName string) (int, error) {
    query := `SELECT id FROM domains WHERE name = ?`
    var id int
    err := app.DB.QueryRow(query, domainName).Scan(&id)
    if err != nil {
        return 0, err
    }
    return id, nil
}

func (app *App) enrichIPData(ip string) (*IPInfo, error) {
    // Check cache first
    cachedInfo, err := app.DB.GetIPInfo(ip)
    if err == nil {
        // Found in cache, update last_checked and return
        cachedInfo.IP = ip
        app.DB.CacheIPInfo(cachedInfo) // Update last_checked
        return cachedInfo, nil
    }

    // Not in cache, fetch from findip.net
    client := resty.New()
    resp, err := client.R().
        SetHeader("User-Agent", "WAF-Backend/1.0").
        Get("https://api.findip.net/" + ip + "/?token=demo") // Using demo token for now

    if err != nil {
        return nil, err
    }

    if resp.StatusCode() != 200 {
        return nil, http.ErrNotSupported
    }

    var apiResponse map[string]interface{}
    if err := json.Unmarshal(resp.Body(), &apiResponse); err != nil {
        return nil, err
    }

    // Extract data from API response
    info := &IPInfo{
        IP:       ip,
        Country:  getStringFromMap(apiResponse, "country_name"),
        ISP:      getStringFromMap(apiResponse, "carrier_name"),
        Org:      getStringFromMap(apiResponse, "company_name"),
        ASN:      getStringFromMap(apiResponse, "asn"),
        UserType: getUserTypeFromAPI(apiResponse),
    }

    // Cache the result
    if err := app.DB.CacheIPInfo(info); err != nil {
        app.Logger.WithError(err).Warn("Failed to cache IP info")
    }

    return info, nil
}

func (app *App) applyBotRules(domainID int, ipInfo *IPInfo) string {
    rules, err := app.DB.GetBotRules(domainID)
    if err != nil {
        app.Logger.WithError(err).Error("Failed to get bot rules")
        return "allow" // Default to allow if we can't check rules
    }

    for _, rule := range rules {
        var matches bool

        switch rule.Field {
        case "country":
            matches = ipInfo.Country == rule.Value
        case "asn":
            matches = ipInfo.ASN == rule.Value
        case "isp":
            matches = ipInfo.ISP == rule.Value
        case "user_type":
            matches = ipInfo.UserType == rule.Value
        }

        if matches {
            return rule.Type // "allow" or "deny"
        }
    }

    return "allow" // Default if no rules match
}

func getStringFromMap(m map[string]interface{}, key string) string {
    if val, exists := m[key]; exists {
        if str, ok := val.(string); ok {
            return str
        }
    }
    return ""
}

func getUserTypeFromAPI(apiResponse map[string]interface{}) string {
    // You might need to adjust this based on the actual findip.net API response
    if val, exists := apiResponse["user_type"]; exists {
        if str, ok := val.(string); ok {
            return str
        }
    }
    return "unknown"
}

func isValidDomain(domain string) bool {
    // Simple domain validation - you might want to use a more robust library
    return len(domain) > 0 && len(domain) <= 253
}

func isValidURL(url string) bool {
    return len(url) > 0 && (len(url) <= 2048)
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
