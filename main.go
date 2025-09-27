package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	DomainHTTPPort  string `json:"domain_http_port"`
	DomainHTTPSPort string `json:"domain_https_port"`
	MgmtHTTPPort    string `json:"mgmt_http_port"`
	MgmtHTTPSPort   string `json:"mgmt_https_port"`

	// ACME configuration
	ACMEEmail       string `json:"acme_email"`
	ACMEDirectory   string `json:"acme_directory"`

	// Security
	RateLimit       int    `json:"rate_limit"`
	EnableCaptcha   bool   `json:"enable_captcha"`
	TLSCipherSuites []uint16 `json:"tls_cipher_suites"`

	// Logging
	LogLevel        string `json:"log_level"`
	LogFormat       string `json:"log_format"`
}

// Default configuration
var defaultConfig = Config{
	DomainHTTPPort:  "80",
	DomainHTTPSPort: "443",
	MgmtHTTPPort:    "3000",
	MgmtHTTPSPort:   "8443",
	ACMEEmail:       "jessicaneedh@gmx.de",
	ACMEDirectory:   "https://acme-v02.api.letsencrypt.org/directory",
	RateLimit:       100,
	EnableCaptcha:   true,
	LogLevel:        "info",
	LogFormat:       "text",
}

// Global configuration
var config Config

// Domain represents a domain configuration
type Domain struct {
	Name         string `json:"name"`
	BackendURL   string `json:"backend_url"`
	Enabled      bool   `json:"enabled"`
	SSLEnabled   bool   `json:"ssl_enabled"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	AutoSSL      bool   `json:"auto_ssl"`
}

// CertificateManager manages SSL certificates
type CertificateManager struct {
	certificates map[string]*tls.Certificate
	mutex        sync.RWMutex
	legoClient   *lego.Client
	httpServer   *http.Server
}

// ACMEUser implements the registration.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   *rsa.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) SetRegistration(reg *registration.Resource) {
	u.Registration = reg
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	// Generate a new RSA private key for ACME registration
	if u.PrivateKey == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil
		}
		u.PrivateKey = privateKey
	}
	return u.PrivateKey
}

// Global certificate manager
var certManager = &CertificateManager{
	certificates: make(map[string]*tls.Certificate),
}

// DomainStore manages domain configurations
type DomainStore struct {
	domains map[string]*Domain
	mutex   sync.RWMutex
}

// Global domain store
var domainStore = &DomainStore{
	domains: make(map[string]*Domain),
}

// DomainStore methods
func (ds *DomainStore) AddDomain(name, backendURL string, enabled bool) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	ds.domains[name] = &Domain{
		Name:       name,
		BackendURL: backendURL,
		Enabled:    enabled,
		SSLEnabled: false,
		AutoSSL:    true,
	}
}

func (ds *DomainStore) RemoveDomain(name string) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	delete(ds.domains, name)
}

func (ds *DomainStore) GetDomain(name string) (*Domain, bool) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()
	domain, exists := ds.domains[name]
	return domain, exists
}

func (ds *DomainStore) GetAllDomains() map[string]*Domain {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*Domain)
	for k, v := range ds.domains {
		result[k] = v
	}
	return result
}

func (ds *DomainStore) UpdateDomain(name string, domain *Domain) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	ds.domains[name] = domain
}

// CertificateManager methods
func (cm *CertificateManager) GetCertificate(domain string) (*tls.Certificate, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	cert, exists := cm.certificates[domain]
	return cert, exists
}

func (cm *CertificateManager) SetCertificate(domain string, cert *tls.Certificate) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.certificates[domain] = cert
}

func (cm *CertificateManager) RemoveCertificate(domain string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.certificates, domain)
}

func (cm *CertificateManager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		if domain == "" {
			return nil, fmt.Errorf("no domain specified in TLS handshake")
		}

		if cert, exists := cm.GetCertificate(domain); exists {
			return cert, nil
		}

		// Try to generate certificate on-demand if auto SSL is enabled
		if domainObj, exists := domainStore.GetDomain(domain); exists && domainObj.AutoSSL && domainObj.SSLEnabled {
			slog.Info("Attempting to generate certificate on-demand", "domain", domainObj.Name)
			if err := cm.GenerateCertificate(domainObj.Name); err != nil {
				slog.Error("Failed to generate certificate on-demand", "domain", domainObj.Name, "error", err)
				return nil, fmt.Errorf("no certificate found for domain: %s", domain)
			}

			// Try again after generation
			if cert, exists := cm.GetCertificate(domain); exists {
				return cert, nil
			}
		}

		return nil, fmt.Errorf("no certificate found for domain: %s", domain)
	}
}

// Custom HTTP-01 challenge provider
type customHTTPProvider struct {
	challengeHandler http.Handler
}

// Present stores the challenge token for HTTP-01 validation
func (p *customHTTPProvider) Present(domain, token, keyAuth string) error {
	SetACMEChallengeToken(token, keyAuth)
	slog.Info("Stored ACME challenge token", "domain", domain, "token", token)
	return nil
}

// CleanUp removes the challenge token after validation
func (p *customHTTPProvider) CleanUp(domain, token, keyAuth string) error {
	RemoveACMEChallengeToken(token)
	slog.Info("Cleaned up ACME challenge token", "domain", domain, "token", token)
	return nil
}

// Initialize ACME client for Let's Encrypt
func (cm *CertificateManager) InitializeACME(email string) error {
	user := &ACMEUser{Email: email}

	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = "4096"

	// Create the lego client
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	// Use custom HTTP-01 challenge provider
	provider := &customHTTPProvider{}
	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		return fmt.Errorf("failed to set HTTP challenge provider: %v", err)
	}

	// Register user
	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return fmt.Errorf("failed to register user: %v", err)
	}

	user.SetRegistration(reg)
	cm.legoClient = client

	return nil
}

// Generate certificate for domain using Let's Encrypt
func (cm *CertificateManager) GenerateCertificate(domain string) error {
	if cm.legoClient == nil {
		return fmt.Errorf("ACME client not initialized")
	}

	// Obtain certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := cm.legoClient.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Parse the certificate
	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Store the certificate
	cm.SetCertificate(domain, &cert)

	slog.Info("Successfully generated SSL certificate", "domain", domain)
	return nil
}

// API Handlers
func getDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	domains := domainStore.GetAllDomains()

	// Convert to slice for JSON response
	var domainList []Domain
	for _, domain := range domains {
		domainList = append(domainList, *domain)
	}

	json.NewEncoder(w).Encode(domainList)
}

func addDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var domain Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Set default values
	if domain.AutoSSL == false {
		domain.AutoSSL = true // Enable auto SSL by default
	}

	domainStore.AddDomain(domain.Name, domain.BackendURL, domain.Enabled)

		// Generate SSL certificate if AutoSSL is enabled
		if domain.AutoSSL && domain.SSLEnabled {
			// Generate certificate in background
			go func() {
				if err := certManager.GenerateCertificate(domain.Name); err != nil {
					slog.Error("Failed to generate SSL certificate", "domain", domain.Name, "error", err)
				}
			}()
		}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain)
}

func removeDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// Remove SSL certificate first
	certManager.RemoveCertificate(name)

	// Remove domain from store
	domainStore.RemoveDomain(name)

	w.WriteHeader(http.StatusNoContent)
}

func updateDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	name := vars["name"]

	var updatedDomain Domain
	if err := json.NewDecoder(r.Body).Decode(&updatedDomain); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if domain exists
	existingDomain, exists := domainStore.GetDomain(name)
	if !exists {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Update the domain
	updatedDomain.Name = name // Ensure name doesn't change
	domainStore.UpdateDomain(name, &updatedDomain)

	// Handle SSL certificate changes
	if updatedDomain.SSLEnabled && updatedDomain.AutoSSL {
		// Remove old certificate if domain name changed (shouldn't happen)
		if existingDomain.Name != name {
			certManager.RemoveCertificate(existingDomain.Name)
		}

		// Generate new certificate in background
		go func() {
			if err := certManager.GenerateCertificate(name); err != nil {
				slog.Error("Failed to generate SSL certificate", "domain", name, "error", err)
			}
		}()
	} else if !updatedDomain.SSLEnabled {
		// Remove certificate if SSL disabled
		certManager.RemoveCertificate(name)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedDomain)
}

func serveWebUI(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("index.html")
	if err != nil {
		http.Error(w, "Web UI not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// healthCheck provides a health check endpoint
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"uptime":    time.Since(startTime).String(),
		"domains":   len(domainStore.GetAllDomains()),
	}

	json.NewEncoder(w).Encode(health)
}

// Global start time for uptime tracking
var startTime = time.Now()

// Proxy handler
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	domain, exists := domainStore.GetDomain(host)
	if !exists {
		http.Error(w, "Domain not configured", http.StatusNotFound)
		return
	}

	if !domain.Enabled {
		http.Error(w, "Domain disabled", http.StatusForbidden)
		return
	}

	// Parse the backend URL
	backendURL, err := url.Parse(domain.BackendURL)
	if err != nil {
		http.Error(w, "Invalid backend URL", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := NewReverseProxy(backendURL)
	proxy.ServeHTTP(w, r)
}

// Captcha middleware
func captchaMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user has already passed captcha (using a cookie)
		captchaCookie, err := r.Cookie("captcha_passed")
		if err == nil && captchaCookie.Value == "true" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if this is a POST request to the captcha endpoint
		if r.Method == "POST" && r.URL.Path == "/captcha" {
			// Set cookie to indicate captcha passed
			http.SetCookie(w, &http.Cookie{
				Name:     "captcha_passed",
				Value:    "true",
				Path:     "/",
				MaxAge:   3600, // 1 hour
				HttpOnly: true,
			})
			w.WriteHeader(http.StatusOK)
			return
		}

		// Serve captcha page
		serveCaptchaPage(w, r)
	})
}

func serveCaptchaPage(w http.ResponseWriter, r *http.Request) {
	captchaHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .captcha-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        .ok-button {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .ok-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="captcha-container">
        <h1>Security Verification</h1>
        <p>For security purposes, please verify that you are human by clicking the button below.</p>
        <form method="post" action="/captcha">
            <button type="submit" class="ok-button">OK - I'm Human</button>
        </form>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(captchaHTML))
}

// NewReverseProxy creates a reverse proxy to the target URL
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/proxy")
		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	modifyResponse := func(res *http.Response) error {
		// Add security headers
		res.Header.Set("X-Proxied-By", "WAF-Proxy")
		return nil
	}

	return &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
	}
}

// getServerIP returns the server's primary IP address
func getServerIP() string {
	serverIP := os.Getenv("SERVER_IP")
	if serverIP != "" {
		return serverIP
	}

	// Try to get the primary non-loopback IP address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0" // Fallback to all interfaces
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// setupLogging configures structured logging
func setupLogging(level, format string) {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// loadConfig loads configuration from environment variables
func loadConfig() {
	// Server configuration
	if port := os.Getenv("DOMAIN_HTTP_PORT"); port != "" {
		config.DomainHTTPPort = port
	}
	if port := os.Getenv("DOMAIN_HTTPS_PORT"); port != "" {
		config.DomainHTTPSPort = port
	}
	if port := os.Getenv("MGMT_HTTP_PORT"); port != "" {
		config.MgmtHTTPPort = port
	}
	if port := os.Getenv("MGMT_HTTPS_PORT"); port != "" {
		config.MgmtHTTPSPort = port
	}

	// ACME configuration
	if email := os.Getenv("ACME_EMAIL"); email != "" {
		config.ACMEEmail = email
	}
	if dir := os.Getenv("ACME_DIRECTORY"); dir != "" {
		config.ACMEDirectory = dir
	}

	// Security
	if rateLimit := os.Getenv("RATE_LIMIT"); rateLimit != "" {
		if rl, err := strconv.Atoi(rateLimit); err == nil {
			config.RateLimit = rl
		}
	}
	if enableCaptcha := os.Getenv("ENABLE_CAPTCHA"); enableCaptcha != "" {
		config.EnableCaptcha = enableCaptcha == "true"
	}

	// Logging
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		config.LogFormat = logFormat
	}
}

// createDomainRouter creates the router for domain proxy traffic
func createDomainRouter() *mux.Router {
	router := mux.NewRouter()

	// ACME challenge endpoint (must be on port 80)
	router.HandleFunc("/.well-known/acme-challenge/{token}", handleACMEChallenge).Methods("GET")

	// Domain proxy handler - handles all other traffic
	router.PathPrefix("/").HandlerFunc(proxyHandler)

	return router
}

// createManagementRouter creates the router for management interface
func createManagementRouter() *mux.Router {
	router := mux.NewRouter()

	// API routes
	router.HandleFunc("/api/domains", getDomains).Methods("GET")
	router.HandleFunc("/api/domains", addDomain).Methods("POST")
	router.HandleFunc("/api/domains/{name}", updateDomain).Methods("PUT")
	router.HandleFunc("/api/domains/{name}", removeDomain).Methods("DELETE")

	// Health check
	router.HandleFunc("/health", healthCheck).Methods("GET")

	// Serve the web UI
	router.HandleFunc("/", serveWebUI).Methods("GET")

	return router
}

// ACME challenge store to hold challenge tokens temporarily
var acmeChallenges = make(map[string]string)
var acmeChallengesMutex sync.RWMutex

// SetACMEChallengeToken stores a challenge token for ACME HTTP-01 validation
func SetACMEChallengeToken(token, content string) {
	acmeChallengesMutex.Lock()
	defer acmeChallengesMutex.Unlock()
	acmeChallenges[token] = content
}

// GetACMEChallengeToken retrieves a challenge token for ACME HTTP-01 validation
func GetACMEChallengeToken(token string) (string, bool) {
	acmeChallengesMutex.RLock()
	defer acmeChallengesMutex.RUnlock()
	content, exists := acmeChallenges[token]
	return content, exists
}

// RemoveACMEChallengeToken removes a challenge token after validation
func RemoveACMEChallengeToken(token string) {
	acmeChallengesMutex.Lock()
	defer acmeChallengesMutex.Unlock()
	delete(acmeChallenges, token)
}

// handleACMEChallenge handles ACME HTTP-01 challenges
func handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	// Extract token from URL path
	vars := mux.Vars(r)
	token := vars["token"]

	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Retrieve the challenge content
	content, exists := GetACMEChallengeToken(token)
	if !exists {
		slog.Warn("ACME challenge token not found", "token", token)
		http.Error(w, "Challenge not found", http.StatusNotFound)
		return
	}

	// Set proper headers for ACME challenge
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))

	slog.Info("Served ACME challenge", "token", token)
}

// rateLimitMiddleware implements basic rate limiting
func rateLimitMiddleware(next http.Handler) http.Handler {
	// Simple in-memory rate limiter (in production, use Redis or similar)
	var mu sync.Mutex
	requests := make(map[string][]time.Time)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.RateLimit <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)
		now := time.Now()

		mu.Lock()
		// Clean old requests (older than 1 minute)
		cutoff := now.Add(-time.Minute)
		if requests[clientIP] != nil {
			var valid []time.Time
			for _, reqTime := range requests[clientIP] {
				if reqTime.After(cutoff) {
					valid = append(valid, reqTime)
				}
			}
			requests[clientIP] = valid
		}

		// Check rate limit
		if len(requests[clientIP]) >= config.RateLimit {
			mu.Unlock()
			slog.Warn("Rate limit exceeded", "client_ip", clientIP)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Add current request
		requests[clientIP] = append(requests[clientIP], now)
		mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Proxied-By", "WAF-Proxy")

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if ip := strings.Split(xff, ",")[0]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// gracefulShutdown handles graceful server shutdown
func gracefulShutdown(servers ...*http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("Server forced to shutdown", "error", err)
		}
	}

	slog.Info("Servers shutdown complete")
}

func main() {
	// Load configuration
	config = defaultConfig
	loadConfig()

	// Setup logging
	setupLogging(config.LogLevel, config.LogFormat)

	slog.Info("Starting WAF Reverse Proxy",
		"domain_http_port", config.DomainHTTPPort,
		"domain_https_port", config.DomainHTTPSPort,
		"mgmt_http_port", config.MgmtHTTPPort,
		"mgmt_https_port", config.MgmtHTTPSPort)

	// Initialize with a default domain
	domainStore.AddDomain("localhost", "http://localhost:8080", true)

	// Initialize ACME client
	if err := certManager.InitializeACME(config.ACMEEmail); err != nil {
		slog.Error("Failed to initialize ACME client", "error", err)
	}

	// Create routers
	domainRouter := createDomainRouter()
	managementRouter := createManagementRouter()

	// Setup CORS for management interface
	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	// Create domain HTTP server (port 80) - handles both ACME challenges and domain traffic
	domainHTTPServer := &http.Server{
		Addr:    ":" + config.DomainHTTPPort,
		Handler: securityHeadersMiddleware(rateLimitMiddleware(domainRouter)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create domain HTTPS server (port 443) - handles SSL domain traffic
	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	domainHTTPSServer := &http.Server{
		Addr:    ":" + config.DomainHTTPSPort,
		Handler: securityHeadersMiddleware(rateLimitMiddleware(http.HandlerFunc(proxyHandler))),
		TLSConfig: tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create management HTTP server
	managementHTTPServer := &http.Server{
		Addr:    ":" + config.MgmtHTTPPort,
		Handler: handlers.CORS(headers, methods, origins)(managementRouter),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create management HTTPS server
	managementHTTPSServer := &http.Server{
		Addr:    ":" + config.MgmtHTTPSPort,
		Handler: handlers.CORS(headers, methods, origins)(managementRouter),
		TLSConfig: tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start servers in goroutines
	go func() {
		slog.Info("Starting domain HTTP server", "port", config.DomainHTTPPort)
		if err := domainHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Domain HTTP server failed", "error", err)
		}
	}()

	go func() {
		slog.Info("Starting domain HTTPS server", "port", config.DomainHTTPSPort)
		if err := domainHTTPSServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("Domain HTTPS server failed", "error", err)
		}
	}()

	go func() {
		slog.Info("Starting management HTTP server", "port", config.MgmtHTTPPort)
		if err := managementHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Management HTTP server failed", "error", err)
		}
	}()

	go func() {
		slog.Info("Starting management HTTPS server", "port", config.MgmtHTTPSPort)
		if err := managementHTTPSServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("Management HTTPS server failed", "error", err)
		}
	}()

	// Wait for shutdown signal
	gracefulShutdown(domainHTTPServer, domainHTTPSServer, managementHTTPServer, managementHTTPSServer)
}
