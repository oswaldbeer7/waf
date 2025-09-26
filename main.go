package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

// Domain represents a domain configuration
type Domain struct {
	Name       string `json:"name"`
	BackendURL string `json:"backend_url"`
	Enabled    bool   `json:"enabled"`
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

	domainStore.AddDomain(domain.Name, domain.BackendURL, domain.Enabled)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain)
}

func removeDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	domainStore.RemoveDomain(name)
	w.WriteHeader(http.StatusNoContent)
}

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

func main() {
	// Initialize with a default domain
	domainStore.AddDomain("localhost", "http://localhost:8080", true)

	router := mux.NewRouter()

	// API routes
	router.HandleFunc("/api/domains", getDomains).Methods("GET")
	router.HandleFunc("/api/domains", addDomain).Methods("POST")
	router.HandleFunc("/api/domains/{name}", removeDomain).Methods("DELETE")

	// Proxy route with captcha middleware
	router.PathPrefix("/").Handler(captchaMiddleware(http.HandlerFunc(proxyHandler)))

	// CORS headers
	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Starting reverse proxy server on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handlers.CORS(headers, methods, origins)(router)))
}
