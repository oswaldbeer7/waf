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

type Config struct {
	DomainHTTPPort  string `json:"domain_http_port"`
	DomainHTTPSPort string `json:"domain_https_port"`
	MgmtHTTPPort    string `json:"mgmt_http_port"`
	MgmtHTTPSPort   string `json:"mgmt_https_port"`
	ACMEEmail       string `json:"acme_email"`
	ACMEDirectory   string `json:"acme_directory"`
	RateLimit       int    `json:"rate_limit"`
	EnableCaptcha   bool   `json:"enable_captcha"`
	TLSCipherSuites []uint16 `json:"tls_cipher_suites"`
	LogLevel        string `json:"log_level"`
	LogFormat       string `json:"log_format"`
}

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

var config Config

type Domain struct {
	Name         string `json:"name"`
	BackendURL   string `json:"backend_url"`
	Enabled      bool   `json:"enabled"`
	SSLEnabled   bool   `json:"ssl_enabled"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	AutoSSL      bool   `json:"auto_ssl"`
	ForceHTTPS   bool   `json:"force_https"`
	CaptchaEnabled bool `json:"captcha_enabled"`
}

type CertificateManager struct {
	certificates map[string]*tls.Certificate
	mutex        sync.RWMutex
	legoClient   *lego.Client
	httpServer   *http.Server
}

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
	if u.PrivateKey == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil
		}
		u.PrivateKey = privateKey
	}
	return u.PrivateKey
}

var certManager = &CertificateManager{
	certificates: make(map[string]*tls.Certificate),
}

type DomainStore struct {
	domains map[string]*Domain
	mutex   sync.RWMutex
}

var domainStore = &DomainStore{
	domains: make(map[string]*Domain),
}

func (ds *DomainStore) AddDomain(name, backendURL string, enabled bool) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	ds.domains[name] = &Domain{
		Name:       name,
		BackendURL: backendURL,
		Enabled:    enabled,
		SSLEnabled: false,
		AutoSSL:    true,
		ForceHTTPS: false,
		CaptchaEnabled: false,
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

		if domainObj, exists := domainStore.GetDomain(domain); exists && domainObj.AutoSSL && domainObj.SSLEnabled {
			slog.Info("Attempting to generate certificate on-demand", "domain", domainObj.Name)
			if err := cm.GenerateCertificate(domainObj.Name); err != nil {
				slog.Error("Failed to generate certificate on-demand", "domain", domainObj.Name, "error", err)
				return nil, fmt.Errorf("no certificate found for domain: %s", domain)
			}

			if cert, exists := cm.GetCertificate(domain); exists {
				return cert, nil
			}
		}

		return nil, fmt.Errorf("no certificate found for domain: %s", domain)
	}
}

type customHTTPProvider struct {
	challengeHandler http.Handler
}

func (p *customHTTPProvider) Present(domain, token, keyAuth string) error {
	SetACMEChallengeToken(token, keyAuth)
	slog.Info("Stored ACME challenge token", "domain", domain, "token", token)
	return nil
}

func (p *customHTTPProvider) CleanUp(domain, token, keyAuth string) error {
	RemoveACMEChallengeToken(token)
	slog.Info("Cleaned up ACME challenge token", "domain", domain, "token", token)
	return nil
}

func (cm *CertificateManager) InitializeACME(email string) error {
	user := &ACMEUser{Email: email}

	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = "4096"

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	provider := &customHTTPProvider{}
	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		return fmt.Errorf("failed to set HTTP challenge provider: %v", err)
	}

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

func (cm *CertificateManager) GenerateCertificate(domain string) error {
	if cm.legoClient == nil {
		return fmt.Errorf("ACME client not initialized")
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := cm.legoClient.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	cm.SetCertificate(domain, &cert)

	slog.Info("Successfully generated SSL certificate", "domain", domain)
	return nil
}

func getDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	domains := domainStore.GetAllDomains()

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

	if domain.AutoSSL == false {
		domain.AutoSSL = true
	}

	domainStore.AddDomain(domain.Name, domain.BackendURL, domain.Enabled)

		if domain.AutoSSL && domain.SSLEnabled {
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

	certManager.RemoveCertificate(name)

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

	existingDomain, exists := domainStore.GetDomain(name)
	if !exists {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	updatedDomain.Name = name
	domainStore.UpdateDomain(name, &updatedDomain)

	if updatedDomain.SSLEnabled && updatedDomain.AutoSSL {
		if existingDomain.Name != name {
			certManager.RemoveCertificate(existingDomain.Name)
		}

		go func() {
			if err := certManager.GenerateCertificate(name); err != nil {
				slog.Error("Failed to generate SSL certificate", "domain", name, "error", err)
			}
		}()
	} else if !updatedDomain.SSLEnabled {
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

var startTime = time.Now()

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

	// Check if HTTP to HTTPS redirect is enabled and request is HTTP
	if domain.ForceHTTPS && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		httpsURL := "https://" + r.Host + r.RequestURI
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		return
	}

	// Check if captcha is enabled for this domain
	if domain.CaptchaEnabled && r.URL.Path == "/" {
		captchaCookie, err := r.Cookie("captcha_passed_" + domain.Name)
		if err == nil && captchaCookie.Value == "true" {
			// Captcha already passed, proceed to backend
		} else if r.Method == "POST" {
			// Set captcha cookie for this domain
			http.SetCookie(w, &http.Cookie{
				Name:     "captcha_passed_" + domain.Name,
				Value:    "true",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
			})
			// Redirect to GET request to show the captcha passed state
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		} else {
			// Serve captcha page
			serveCaptchaPage(w, r, domain.Name)
			return
		}
	}

	backendURL, err := url.Parse(domain.BackendURL)
	if err != nil {
		http.Error(w, "Invalid backend URL", http.StatusInternalServerError)
		return
	}

	proxy := NewReverseProxy(backendURL)
	proxy.ServeHTTP(w, r)
}

func captchaMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captchaCookie, err := r.Cookie("captcha_passed")
		if err == nil && captchaCookie.Value == "true" {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == "POST" && r.URL.Path == "/captcha" {
			http.SetCookie(w, &http.Cookie{
				Name:     "captcha_passed",
				Value:    "true",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
			})
			w.WriteHeader(http.StatusOK)
			return
		}

		serveCaptchaPage(w, r, "")
	})
}

func serveCaptchaPage(w http.ResponseWriter, r *http.Request, domainName string) {
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
        <form method="post" action="/">
            <button type="submit" class="ok-button">OK - I'm Human</button>
        </form>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(captchaHTML))
}

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
		res.Header.Set("X-Proxied-By", "WAF-Proxy")
		return nil
	}

	return &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
	}
}

func getServerIP() string {
	serverIP := os.Getenv("SERVER_IP")
	if serverIP != "" {
		return serverIP
	}

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

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

func loadConfig() {
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

	if email := os.Getenv("ACME_EMAIL"); email != "" {
		config.ACMEEmail = email
	}
	if dir := os.Getenv("ACME_DIRECTORY"); dir != "" {
		config.ACMEDirectory = dir
	}

	if rateLimit := os.Getenv("RATE_LIMIT"); rateLimit != "" {
		if rl, err := strconv.Atoi(rateLimit); err == nil {
			config.RateLimit = rl
		}
	}
	if enableCaptcha := os.Getenv("ENABLE_CAPTCHA"); enableCaptcha != "" {
		config.EnableCaptcha = enableCaptcha == "true"
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		config.LogFormat = logFormat
	}
}

func createDomainRouter() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/.well-known/acme-challenge/{token}", handleACMEChallenge).Methods("GET")

	router.PathPrefix("/").HandlerFunc(proxyHandler)

	return router
}

func createManagementRouter() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/api/domains", getDomains).Methods("GET")
	router.HandleFunc("/api/domains", addDomain).Methods("POST")
	router.HandleFunc("/api/domains/{name}", updateDomain).Methods("PUT")
	router.HandleFunc("/api/domains/{name}", removeDomain).Methods("DELETE")

	router.HandleFunc("/health", healthCheck).Methods("GET")

	router.HandleFunc("/", serveWebUI).Methods("GET")

	return router
}

var acmeChallenges = make(map[string]string)
var acmeChallengesMutex sync.RWMutex

func SetACMEChallengeToken(token, content string) {
	acmeChallengesMutex.Lock()
	defer acmeChallengesMutex.Unlock()
	acmeChallenges[token] = content
}

func GetACMEChallengeToken(token string) (string, bool) {
	acmeChallengesMutex.RLock()
	defer acmeChallengesMutex.RUnlock()
	content, exists := acmeChallenges[token]
	return content, exists
}

func RemoveACMEChallengeToken(token string) {
	acmeChallengesMutex.Lock()
	defer acmeChallengesMutex.Unlock()
	delete(acmeChallenges, token)
}

func handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	content, exists := GetACMEChallengeToken(token)
	if !exists {
		slog.Warn("ACME challenge token not found", "token", token)
		http.Error(w, "Challenge not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))

	slog.Info("Served ACME challenge", "token", token)
}

func rateLimitMiddleware(next http.Handler) http.Handler {
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

		if len(requests[clientIP]) >= config.RateLimit {
			mu.Unlock()
			slog.Warn("Rate limit exceeded", "client_ip", clientIP)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		requests[clientIP] = append(requests[clientIP], now)
		mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Proxied-By", "WAF-Proxy")

		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.Split(xff, ",")[0]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

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
	config = defaultConfig
	loadConfig()

	setupLogging(config.LogLevel, config.LogFormat)

	slog.Info("Starting WAF Reverse Proxy",
		"domain_http_port", config.DomainHTTPPort,
		"domain_https_port", config.DomainHTTPSPort,
		"mgmt_http_port", config.MgmtHTTPPort,
		"mgmt_https_port", config.MgmtHTTPSPort)

	domainStore.AddDomain("localhost", "http://localhost:8080", true)
	// Update localhost domain to have ForceHTTPS enabled by default
	if domain, exists := domainStore.GetDomain("localhost"); exists {
		domain.ForceHTTPS = true
		domainStore.UpdateDomain("localhost", domain)
	}

	if err := certManager.InitializeACME(config.ACMEEmail); err != nil {
		slog.Error("Failed to initialize ACME client", "error", err)
	}

	domainRouter := createDomainRouter()
	managementRouter := createManagementRouter()

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	domainHTTPServer := &http.Server{
		Addr:    ":" + config.DomainHTTPPort,
		Handler: securityHeadersMiddleware(rateLimitMiddleware(domainRouter)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

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

	managementHTTPServer := &http.Server{
		Addr:    ":" + config.MgmtHTTPPort,
		Handler: handlers.CORS(headers, methods, origins)(managementRouter),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	managementHTTPSServer := &http.Server{
		Addr:    ":" + config.MgmtHTTPSPort,
		Handler: handlers.CORS(headers, methods, origins)(managementRouter),
		TLSConfig: tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

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

	gracefulShutdown(domainHTTPServer, domainHTTPSServer, managementHTTPServer, managementHTTPSServer)
}
