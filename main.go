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
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelDebug) // Set log level to DEBUG
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("Starting Birdhole Simplified...")

	// Load configuration
	if err := config.Load("./config.toml"); err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	appCfg := &config.AppConfig // Use pointer for easier passing
	logger.Info("Configuration loaded", "port", appCfg.Port, "db_path", appCfg.BitcaskPath)

	// Initialize storage
	store, err := storage.NewStorage(appCfg, logger)
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

	// Create handlers
	handlerDeps := handlers.New(store, appCfg, logger, tmpl)

	// Create middleware instance
	mw := middleware.New(logger)

	// Setup routing
	mux := http.NewServeMux()

	// --- Public routes (mostly) ---
	mux.Handle("GET /{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.FileServingHandler))))
	// Thumbnail - Now public
	mux.Handle("GET /thumbnail/{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.ThumbnailHandler))))
	// Static files (no auth needed)
	staticFS := http.Dir("./static")
	mux.Handle("/static/", mw.ClientIP(mw.Logging(handlerDeps.StaticHandler(staticFS)))) // Note: ClientIP might be overkill for static

	// --- Gallery routes - Now public ---
	// galleryAuth middleware removed
	mux.Handle("GET /gallery", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.GalleryHandler))))
	mux.Handle("GET /gallery/items", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.GalleryItemsHandler))))
	mux.Handle("GET /detail/{filename}", mw.ClientIP(mw.Logging(http.HandlerFunc(handlerDeps.DetailViewHandler))))

	// --- Authenticated routes ---
	// Upload (requires upload key)
	mux.Handle("POST /hole", mw.ClientIP(mw.AuthCheck(appCfg, false, true, false)(mw.Logging(http.HandlerFunc(handlerDeps.UploadHandler)))))
	// Delete (requires admin key)
	mux.Handle("DELETE /{filename}", mw.ClientIP(mw.AuthCheck(appCfg, false, false, true)(mw.Logging(http.HandlerFunc(handlerDeps.DeleteHandler)))))

	// Apply global middleware (Recovery should be first, then SecurityHeaders)
	// Note: ClientIP was moved to wrap individual routes for logging accuracy
	finalHandler := mw.Recovery(mw.SecurityHeaders(mux))

	// Configure server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", appCfg.ListenAddr, appCfg.Port),
		Handler:      finalHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start expiry check goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()                            // Ensure context is cancelled on exit
	go store.CheckExpiry(ctx, 10*time.Minute) // Check every 10 mins

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
