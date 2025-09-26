package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gorilla/mux"
    "github.com/gorilla/handlers"
    "github.com/sirupsen/logrus"
    "github.com/joho/godotenv"
)

type App struct {
    DB *Database
    Logger *logrus.Logger
    CaddyAdminAPI string
}

type Domain struct {
    ID        int    `json:"id"`
    Name      string `json:"name"`
    OriginURL string `json:"origin_url"`
    CreatedAt string `json:"created_at"`
}

type RequestLog struct {
    ID        int    `json:"id"`
    DomainID  int    `json:"domain_id"`
    IP        string `json:"ip"`
    Path      string `json:"path"`
    UserAgent string `json:"user_agent"`
    Country   string `json:"country"`
    ISP       string `json:"isp"`
    Org       string `json:"org"`
    ASN       string `json:"asn"`
    UserType  string `json:"user_type"`
    Decision  string `json:"decision"`
    Timestamp string `json:"timestamp"`
}

type BotRule struct {
    ID       int    `json:"id"`
    DomainID int    `json:"domain_id"`
    Type     string `json:"type"` // allow or deny
    Field    string `json:"field"` // country, asn, isp, user_type
    Value    string `json:"value"`
}

type IPInfo struct {
    IP       string `json:"ip"`
    Country  string `json:"country"`
    ISP      string `json:"isp"`
    Org      string `json:"org"`
    ASN      string `json:"asn"`
    UserType string `json:"user_type"`
}

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, using system environment variables")
    }

    // Initialize logger
    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    logger.SetOutput(os.Stdout)

    // Initialize database
    dbPath := getEnv("DB_PATH", "/app/data/waf.db")
    database, err := InitializeDB(dbPath)
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    defer database.Close()

    // Create app instance
    app := &App{
        DB: database,
        Logger: logger,
        CaddyAdminAPI: getEnv("CADDY_ADMIN_API", "http://localhost:2019"),
    }

    // Setup HTTP routes
    router := mux.NewRouter()

    // Health check
    router.HandleFunc("/api/health", app.healthCheck).Methods("GET")

    // Domain management
    router.HandleFunc("/api/domains", app.getDomains).Methods("GET")
    router.HandleFunc("/api/domains", app.createDomain).Methods("POST")
    router.HandleFunc("/api/domains/{id}", app.updateDomain).Methods("PUT")
    router.HandleFunc("/api/domains/{id}", app.deleteDomain).Methods("DELETE")

    // Request logs
    router.HandleFunc("/api/logs", app.getLogs).Methods("GET")
    router.HandleFunc("/api/logs/{domain_id}", app.getDomainLogs).Methods("GET")

    // Statistics
    router.HandleFunc("/api/stats", app.getStats).Methods("GET")
    router.HandleFunc("/api/stats/{domain_id}", app.getDomainStats).Methods("GET")

    // Bot rules
    router.HandleFunc("/api/bots/rules", app.getBotRules).Methods("GET")
    router.HandleFunc("/api/bots/rules", app.createBotRule).Methods("POST")
    router.HandleFunc("/api/bots/rules/{id}", app.updateBotRule).Methods("PUT")
    router.HandleFunc("/api/bots/rules/{id}", app.deleteBotRule).Methods("DELETE")

    // Log ingestion endpoint (called by Caddy)
    router.HandleFunc("/api/ingest", app.ingestLog).Methods("POST")

    // CORS middleware
    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"*"}),
        handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}),
    )(router)

    // Server configuration
    port := getEnv("PORT", "8080")
    server := &http.Server{
        Addr:         ":" + port,
        Handler:      corsHandler,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    // Start server in a goroutine
    go func() {
        logger.Info("Starting WAF Backend API on port " + port)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("Could not start server:", err)
        }
    }()

    // Wait for interrupt signal to gracefully shutdown the server
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    logger.Info("Shutting down server...")

    // Graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    if err := server.Shutdown(ctx); err != nil {
        logger.Fatal("Server forced to shutdown:", err)
    }

    logger.Info("Server exited")
}

// Health check endpoint
func (app *App) healthCheck(w http.ResponseWriter, r *http.Request) {
    response := map[string]string{"status": "healthy", "service": "waf-backend"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Helper function to get environment variables
func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
