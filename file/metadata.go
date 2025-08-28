package file

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/dsoprea/go-exif/v3"
	pngstructure "github.com/dsoprea/go-png-image-structure/v2"
)

// MircifyMetadata represents the JSON structure embedded in PNG Comment field
type MircifyMetadata struct {
	Timestamp string `json:"timestamp"`
	Generator string `json:"generator"`
	Version   string `json:"version"`
	IRC       string `json:"irc,omitempty"`
	ANSI      string `json:"ansi,omitempty"`
}

// Validate checks if metadata is from ComfyUI-Mircify
func (m *MircifyMetadata) Validate() bool {
	return m.Generator == "ComfyUI-Mircify" && m.Version != ""
}

// HasContent checks if metadata contains extractable content
func (m *MircifyMetadata) HasContent() bool {
	return m.IRC != "" || m.ANSI != ""
}

// DerivedFile tracks extracted content files
type DerivedFile struct {
	Type     string `json:"type"`     // "irc" or "ansi"
	Filename string `json:"filename"` // Generated filename for derived content
	Size     int64  `json:"size"`     // Size of derived content
	Created  int64  `json:"created"`  // Timestamp when derived file was created
}

// PNGMetadataExtractor handles PNG metadata extraction
type PNGMetadataExtractor struct {
	log *slog.Logger
}

// NewPNGMetadataExtractor creates a new PNG metadata extractor
func NewPNGMetadataExtractor(logger *slog.Logger) *PNGMetadataExtractor {
	return &PNGMetadataExtractor{
		log: logger.With("component", "png_metadata"),
	}
}

// ExtractMircifyMetadata attempts to extract ComfyUI-Mircify metadata from PNG bytes
// If no metadata is found, returns nil without fallback conversion
func (e *PNGMetadataExtractor) ExtractMircifyMetadata(ctx context.Context, pngData []byte) (*MircifyMetadata, error) {
	log := e.log.With("function", "ExtractMircifyMetadata")

	// Method 1: Parse PNG chunks directly
	if metadata, err := e.extractFromPNGChunks(pngData); err == nil && metadata != nil {
		log.Debug("Successfully extracted metadata from PNG chunks")
		return metadata, nil
	}

	// Method 2: Try EXIF extraction as fallback
	if metadata, err := e.extractFromEXIF(pngData); err == nil && metadata != nil {
		log.Debug("Successfully extracted metadata from EXIF")
		return metadata, nil
	}

	log.Debug("No ComfyUI-Mircify metadata found in PNG - download buttons will not be available")
	return nil, fmt.Errorf("no ComfyUI-Mircify metadata found")
}

// extractFromPNGChunks parses PNG structure and looks for text chunks
func (e *PNGMetadataExtractor) extractFromPNGChunks(pngData []byte) (*MircifyMetadata, error) {
	log := e.log.With("method", "png_chunks")

	// Parse PNG structure
	pmp := pngstructure.NewPngMediaParser()
	intfc, err := pmp.ParseBytes(pngData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PNG structure: %w", err)
	}

	chunks := intfc.(*pngstructure.ChunkSlice)
	log.Debug("Parsed PNG structure", "chunk_count", len(chunks.Chunks()))

	// Look for text chunks
	for _, chunk := range chunks.Chunks() {
		chunkType := string(chunk.Type)
		log.Debug("Examining PNG chunk", "type", chunkType, "size", len(chunk.Data))

		// Check iTXt, tEXt, and zTXt chunks
		if chunkType == "iTXt" || chunkType == "tEXt" || chunkType == "zTXt" {
			if metadata := e.parseTextChunk(chunk.Data, chunkType); metadata != nil {
				return metadata, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid text chunks found")
}

// parseTextChunk attempts to parse a text chunk for Comment data
func (e *PNGMetadataExtractor) parseTextChunk(chunkData []byte, chunkType string) *MircifyMetadata {
	log := e.log.With("chunk_type", chunkType)

	// Look for Comment keyword followed by null bytes and JSON
	// Format: Comment\0\0\0\0\0{JSON_DATA}
	commentPrefix := []byte("Comment\x00")

	if !bytes.HasPrefix(chunkData, commentPrefix) {
		return nil
	}

	log.Debug("Found Comment chunk")

	// Skip past "Comment" and null bytes to find JSON start
	jsonStart := -1
	for i := len(commentPrefix); i < len(chunkData); i++ {
		if chunkData[i] == '{' {
			jsonStart = i
			break
		}
	}

	if jsonStart == -1 {
		log.Debug("No JSON data found after Comment prefix")
		return nil
	}

	jsonData := chunkData[jsonStart:]
	log.Debug("Found JSON data", "size", len(jsonData))

	var metadata MircifyMetadata
	if err := json.Unmarshal(jsonData, &metadata); err != nil {
		log.Debug("Failed to parse JSON metadata", "error", err)
		return nil
	}

	if !metadata.Validate() {
		log.Debug("Invalid metadata - not from ComfyUI-Mircify", "generator", metadata.Generator)
		return nil
	}

	log.Debug("Successfully parsed ComfyUI-Mircify metadata",
		"has_irc", metadata.IRC != "",
		"has_ansi", metadata.ANSI != "",
		"irc_length", len(metadata.IRC),
		"ansi_length", len(metadata.ANSI))

	return &metadata
}

// extractFromEXIF attempts EXIF extraction as fallback
func (e *PNGMetadataExtractor) extractFromEXIF(pngData []byte) (*MircifyMetadata, error) {
	log := e.log.With("method", "exif")

	// Parse EXIF data from PNG
	rawExif, err := exif.SearchAndExtractExif(pngData)
	if err != nil {
		return nil, fmt.Errorf("no EXIF data found: %w", err)
	}

	// Parse EXIF entries
	entries, _, err := exif.GetFlatExifData(rawExif, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EXIF data: %w", err)
	}

	log.Debug("Parsed EXIF data", "entry_count", len(entries))

	// Look for Comment or Description fields
	for _, entry := range entries {
		if entry.TagName == "UserComment" || entry.TagName == "ImageDescription" {
			if jsonStr, ok := entry.Value.(string); ok && strings.HasPrefix(jsonStr, "{") {
				var metadata MircifyMetadata
				if json.Unmarshal([]byte(jsonStr), &metadata) == nil && metadata.Validate() {
					log.Debug("Found metadata in EXIF", "tag", entry.TagName)
					return &metadata, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ComfyUI-Mircify metadata in EXIF")
}

// GenerateDerivedFilename creates a filename for derived content
func GenerateDerivedFilename(originalFilename string, message string, contentType string) string {
	// Get base filename without extension
	base := strings.TrimSuffix(originalFilename, filepath.Ext(originalFilename))

	// Use message if provided, otherwise use base filename
	slug := base
	if message != "" {
		slug = slugify(message)
		if len(slug) > 255 {
			slug = slug[:255]
		}
	}

	// Add appropriate extension
	ext := ".txt"
	if contentType == "ansi" {
		ext = ".ans"
	}

	return slug + ext
}

// slugify converts a string to a filesystem-safe slug
func slugify(s string) string {
	// Convert to lowercase and replace invalid characters with hyphens
	var result strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else if result.Len() > 0 && result.String()[result.Len()-1] != '-' {
			result.WriteRune('-')
		}
	}

	// Trim trailing hyphens
	slug := strings.TrimRight(result.String(), "-")
	if slug == "" {
		return "extracted-content"
	}
	return slug
}
