package file

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Info represents the metadata for a stored file
// Keep this consistent with the original structure to ensure compatibility.
type Info struct {
	Name        string            `json:"name"`                   // Unique filename (e.g., randomname.ext)
	Description string            `json:"description,omitempty"`  // User-provided description
	Message     string            `json:"message,omitempty"`      // Optional user-provided message
	Hidden      bool              `json:"hidden"`                 // Flag to hide from public gallery view
	Tags        []string          `json:"tags,omitempty"`         // User-provided tags
	Meta        map[string]string `json:"meta,omitempty"`         // Arbitrary user-provided key-value metadata (ensure keys/values are sanitized)
	MimeType    string            `json:"mime_type"`              // Detected MIME type of the file
	Size        int64             `json:"size"`                   // Original file size in bytes (before compression)
	Timestamp   int64             `json:"timestamp"`              // Unix timestamp of upload time
	KeyExpiry   int64             `json:"key_expiry"`             // Unix timestamp when the file should expire
	Views       int               `json:"views"`                  // View count (NOTE: Simplified version removes view increment logic, but field kept for potential future use/data compatibility)
	Width       int               `json:"width,omitempty"`        // Image width (if applicable)
	Height      int               `json:"height,omitempty"`       // Image height (if applicable)
	Hash        string            `json:"hash,omitempty"`         // Optional file hash (consider adding SHA256 calculation on upload)
	ProcessedAt int64             `json:"processed_at,omitempty"` // Optional timestamp for when processing (like thumbnailing) finished
	Panorama    bool              `json:"panorama,omitempty"`     // Panorama flag for detail view
}

// GetExtension returns the file extension
func (i *Info) GetExtension() string {
	return strings.ToLower(filepath.Ext(i.Name))
}

// IsText checks if the MimeType is text-based.
func (i *Info) IsText() bool {
	return strings.HasPrefix(i.MimeType, "text/")
}

// IsExpired checks if the file has expired based on KeyExpiry
func (i *Info) IsExpired() bool {
	// Handle potential zero expiry (never expires)
	if i.KeyExpiry == 0 {
		return false
	}
	return time.Now().Unix() > i.KeyExpiry
}

// Validate performs basic validation on required fields
func (i *Info) Validate() error {
	var errors []string
	if i.Name == "" {
		errors = append(errors, "name is required")
	}
	if i.MimeType == "" {
		errors = append(errors, "mime type is required")
	}
	if i.Timestamp <= 0 {
		errors = append(errors, "timestamp must be positive")
	}
	// KeyExpiry can be 0 (never), so only check if it's non-zero and before timestamp
	if i.KeyExpiry != 0 && i.KeyExpiry <= i.Timestamp {
		errors = append(errors, "expiry must be after timestamp")
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errors, ", "))
	}
	return nil
}
