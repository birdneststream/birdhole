package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config holds the application configuration.
// Note: Field names must be capitalized to be exported and parsed by the TOML library.
type Config struct {
	Port            string `toml:"Port"`
	ListenAddr      string `toml:"ListenAddr"`
	DefaultExpiry   string `toml:"DefaultExpiry"` // Parsed into duration later
	BitcaskPath     string `toml:"BitcaskPath"`
	UploadKey       string `toml:"UploadKey"`
	GalleryKey      string `toml:"GalleryKey"`
	AdminKey        string `toml:"AdminKey"`
	MaxUploadSizeMB int64  `toml:"MaxUploadSizeMB"`
	BaseURL         string `toml:"BaseURL"`

	// Parsed durations
	DefaultExpiryDuration time.Duration `toml:"-"` // Ignored by TOML parser
}

// AppConfig holds the global application configuration.
var AppConfig Config

// Load reads the configuration from the specified path.
// It applies defaults for missing optional values and validates required ones.
func Load(configPath string) error {
	// Set defaults
	AppConfig = Config{
		Port:            "8080",
		ListenAddr:      "0.0.0.0",
		DefaultExpiry:   "24h",
		BitcaskPath:     "./birdhole.db",
		MaxUploadSizeMB: 100,
		BaseURL:         "/",
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

	// Ensure MaxUploadSizeMB is reasonable
	if AppConfig.MaxUploadSizeMB <= 0 {
		AppConfig.MaxUploadSizeMB = 100 // Reset to default if invalid
	}

	return nil
}
