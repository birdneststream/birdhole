package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config holds the application configuration.
// Note: Field names must be capitalized to be exported and parsed by the TOML library.
type Config struct {
	Port                   string `toml:"Port"`
	ListenAddr             string `toml:"ListenAddr"`
	DefaultExpiry          string `toml:"DefaultExpiry"` // Parsed into duration later
	BitcaskPath            string `toml:"BitcaskPath"`
	FilesPath              string `toml:"FilesPath"`      // New: Path for storing actual files
	ThumbnailsPath         string `toml:"ThumbnailsPath"` // New: Path for storing thumbnails
	UploadKey              string `toml:"UploadKey"`
	GalleryKey             string `toml:"GalleryKey"`
	AdminKey               string `toml:"AdminKey"`
	MaxUploadSizeMB        int64  `toml:"MaxUploadSizeMB"`
	BaseURL                string `toml:"BaseURL"`
	LogLevel               string `toml:"LogLevel"`                         // New: Log level (debug, info, warn, error)
	ExpiryCheckInterval    string `toml:"ExpiryCheckInterval"`              // New: How often to check for expired files
	ViewCounterSalt        string `toml:"ViewCounterSalt"`                  // New: Secret salt for hashing IPs
	GalleryRateLimitCount  int    `toml:"GalleryRateLimitCount,omitempty"`  // ADDED: Max gallery key attempts per window
	GalleryRateLimitWindow string `toml:"GalleryRateLimitWindow,omitempty"` // ADDED: Gallery rate limit window (e.g., "1m")

	// Parsed durations & values
	DefaultExpiryDuration          time.Duration `toml:"-"` // Ignored by TOML parser
	ExpiryCheckIntervalDuration    time.Duration `toml:"-"` // Ignored by TOML parser
	LogLevelParsed                 slog.Level    `toml:"-"` // Ignored by TOML parser
	GalleryRateLimitWindowDuration time.Duration `toml:"-"` // ADDED: Parsed gallery rate limit window
}

// AppConfig holds the global application configuration.
var AppConfig Config

// parseLogLevel converts a string level to slog.Level.
func parseLogLevel(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo // Default to Info if unknown
	}
}

// Load reads the configuration from the specified path.
// It applies defaults for missing optional values and validates required ones.
func Load(configPath string) error {
	// Set defaults
	AppConfig = Config{
		Port:                   "8080",
		ListenAddr:             "0.0.0.0",
		DefaultExpiry:          "24h",
		BitcaskPath:            "./birdhole.db",
		FilesPath:              "./files",      // Default files directory
		ThumbnailsPath:         "./thumbnails", // Default thumbnails directory
		MaxUploadSizeMB:        100,
		BaseURL:                "/",
		LogLevel:               "info",                              // Default log level
		ExpiryCheckInterval:    "10m",                               // Default expiry check interval
		ViewCounterSalt:        "default-insecure-change-this-salt", // Default salt (INSECURE)
		GalleryRateLimitCount:  10,                                  // ADDED: Default 10 attempts
		GalleryRateLimitWindow: "1m",                                // ADDED: Default 1 minute window
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); err == nil {
		// File exists, decode it
		if _, err := toml.DecodeFile(configPath, &AppConfig); err != nil {
			return fmt.Errorf("error decoding config file '%s': %w", configPath, err)
		}
	} else if !os.IsNotExist(err) {
		// Other error accessing file (permissions?)
		return fmt.Errorf("error checking config file '%s': %w", configPath, err)
	} // If file does not exist, we just use the defaults set above.

	// Validate required fields
	if AppConfig.UploadKey == "" {
		return fmt.Errorf("config error: UploadKey must be set")
	}
	if AppConfig.AdminKey == "" {
		return fmt.Errorf("config error: AdminKey must be set")
	}

	// Validate ViewCounterSalt
	if AppConfig.ViewCounterSalt == "" || AppConfig.ViewCounterSalt == "default-insecure-change-this-salt" {
		// Warn if salt is empty or default, but don't fail load
		// Consider making this a fatal error in production environments.
		slog.Warn("Security warning: ViewCounterSalt is empty or using the default insecure value. Please set a strong secret salt in your configuration.")
	}

	// Ensure BaseURL has a trailing slash if set and not just "/"
	if AppConfig.BaseURL != "/" && !strings.HasSuffix(AppConfig.BaseURL, "/") {
		AppConfig.BaseURL += "/"
	}

	// Parse DefaultExpiry string into duration
	if AppConfig.DefaultExpiry != "" {
		duration, err := time.ParseDuration(AppConfig.DefaultExpiry)
		if err != nil {
			return fmt.Errorf("config error: invalid DefaultExpiry duration '%s': %w", AppConfig.DefaultExpiry, err)
		}
		AppConfig.DefaultExpiryDuration = duration
	} else {
		// Should not happen if default is set correctly, but handle anyway
		AppConfig.DefaultExpiryDuration = 24 * time.Hour
	}

	// Parse ExpiryCheckInterval string into duration
	if AppConfig.ExpiryCheckInterval != "" {
		duration, err := time.ParseDuration(AppConfig.ExpiryCheckInterval)
		if err != nil {
			return fmt.Errorf("config error: invalid ExpiryCheckInterval duration '%s': %w", AppConfig.ExpiryCheckInterval, err)
		}
		AppConfig.ExpiryCheckIntervalDuration = duration
	} else {
		// Should not happen if default is set correctly, but handle anyway
		AppConfig.ExpiryCheckIntervalDuration = 10 * time.Minute
	}

	// Parse LogLevel string into slog.Level
	AppConfig.LogLevelParsed = parseLogLevel(AppConfig.LogLevel)

	// Parse GalleryRateLimitWindow string into duration
	if AppConfig.GalleryRateLimitWindow != "" {
		duration, err := time.ParseDuration(AppConfig.GalleryRateLimitWindow)
		if err != nil {
			// Don't fail load, just log warning and maybe disable limiting?
			// For now, just log and use default duration.
			slog.Warn("Invalid GalleryRateLimitWindow duration, using default", "input", AppConfig.GalleryRateLimitWindow, "error", err)
			AppConfig.GalleryRateLimitWindowDuration = 1 * time.Minute // Fallback to default
		} else {
			AppConfig.GalleryRateLimitWindowDuration = duration
		}
	} else {
		AppConfig.GalleryRateLimitWindowDuration = 1 * time.Minute // Default if empty
	}

	// Ensure MaxUploadSizeMB is reasonable
	if AppConfig.MaxUploadSizeMB <= 0 {
		AppConfig.MaxUploadSizeMB = 100 // Reset to default if invalid
	}

	return nil
}
