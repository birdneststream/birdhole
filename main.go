package main

import (
	"birdhole/config"
	"birdhole/handlers"
	"birdhole/markdown"
	"birdhole/middleware"
	"birdhole/storage"
	"birdhole/templates"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Setup structured logging
	logLevel := new(slog.LevelVar) // Use LevelVar to allow potential dynamic changes
	// loglevel is set after loading config
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	
	// Set GOMAXPROCS to use all available CPU cores
	// This is usually the default, but making it explicit
	// runtime.GOMAXPROCS(runtime.NumCPU())

	logger.Info("Starting Birdhole Simplified...")

	// Load configuration
	if err := config.Load("./config.toml"); err != nil {
		// Use default logger here as config loading failed before level was set
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	// Set log level from config AFTER loading it
	logLevel.Set(config.AppConfig.LogLevelParsed)
	logger.Info("Configuration loaded",
		"port", config.AppConfig.Port,
		"db_path", config.AppConfig.BitcaskPath,
		"log_level", config.AppConfig.LogLevel,
		"expiry_check", config.AppConfig.ExpiryCheckIntervalDuration)

	// Initialize storage
	store, err := storage.NewStorage(&config.AppConfig, logger)
	if err != nil {
		logger.Error("Failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close() // Ensure DB is closed on exit

	// Initialize markdown renderer
	markdown.Init()
	logger.Info("Markdown renderer initialized")

	// Load HTML templates
	if err := templates.Load(); err != nil {
		logger.Error("Failed to load HTML templates", "error", err)
		os.Exit(1)
	}
	// Get the loaded templates
	tmpl := templates.Get()
	if tmpl == nil {
		logger.Error("Failed to get loaded templates (nil)")
		os.Exit(1)
	}

	// Create handlers (passing config directly)
	handlerDeps := handlers.New(store, &config.AppConfig, logger, tmpl)

	// Create middleware instance
	mw := middleware.New(logger, &config.AppConfig)

	// Setup routing
	mux := http.NewServeMux()

	// --- Root Path ---
	mux.Handle("GET /", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.WelcomeHandler))))

	// --- Public routes (mostly) ---
	mux.Handle("GET /{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.FileServingHandler))))
	// Thumbnail - Now public
	mux.Handle("GET /thumbnail/{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.ThumbnailHandler))))
	// Static files (no auth needed)
	staticFS := http.Dir("./static")
	mux.Handle("GET /static/", mw.ClientIP(mw.Logging(handlerDeps.StaticHandler(staticFS)))) // CHANGED: Explicitly use GET method

	// --- Gallery routes - Now public ---
	// galleryAuth middleware removed
	mux.Handle("GET /gallery", mw.GalleryRateLimit(mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.GalleryHandler)))))
	mux.Handle("GET /gallery/items", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.GalleryItemsHandler))))
	mux.Handle("GET /gallery/load-more", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.LoadMoreItemsHandler))))
	mux.Handle("GET /detail/{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.DetailViewHandler))))

	// --- Authenticated routes ---
	// Upload (requires upload key) - now async with background thumbnail generation
	mux.Handle("POST /hole", mw.ClientIP(mw.RateLimit(mw.AuthCheck(&config.AppConfig, false, true, false)(mw.Logging(http.HandlerFunc(handlerDeps.UploadHandler))))))
	// Delete (requires admin key)
	mux.Handle("DELETE /{filename}", mw.ClientIP(mw.RateLimit(mw.AuthCheck(&config.AppConfig, false, false, true)(mw.Logging(http.HandlerFunc(handlerDeps.DeleteHandler))))))

	// Apply global middleware (Recovery should be first, then SecurityHeaders)
	// Note: ClientIP was moved to wrap individual routes for logging accuracy
	// Note: RateLimit applied per-route to sensitive endpoints
	finalHandler := mw.Recovery(mw.SecurityHeaders(mux))

	// Configure server
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", config.AppConfig.ListenAddr, config.AppConfig.Port),
		Handler:           finalHandler,
		ReadTimeout:       30 * time.Second,  // Increased from 5s to handle uploads
		ReadHeaderTimeout: 10 * time.Second,  // Added header timeout
		WriteTimeout:      60 * time.Second,  // Increased from 30s for large files
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB max header
	}

	// Start expiry check goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()                                                          // Ensure context is cancelled on exit
	go store.CheckExpiry(ctx, config.AppConfig.ExpiryCheckIntervalDuration) // Use config value

	// Start server in a goroutine
	go func() {
		logger.Info("Server starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // Block until signal is received

	logger.Warn("Shutdown signal received, starting graceful shutdown...")

	// Context for shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second) // Allow 15 seconds for shutdown
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Server gracefully stopped")
}
