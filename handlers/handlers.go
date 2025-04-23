package handlers

import (
	"birdhole/config"
	"birdhole/file"
	"birdhole/markdown"
	"birdhole/middleware"
	"birdhole/storage"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "golang.org/x/image/webp"

	"github.com/disintegration/imaging"
)

// Define specific error for invalid key access
var ErrInvalidAccessKey = errors.New("invalid gallery access key")

// Regex to validate expected filename format: 6-16 lowercase base32 chars + optional extension.
var validFilenameRegex = regexp.MustCompile(`^[a-z0-9]{6,16}(\.[a-zA-Z0-9]+)?$`)

// getClientIP extracts the client IP address from the request, checking common headers.
func getClientIP(r *http.Request) string {
	// Check Cloudflare header first
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF can contain a comma-separated list, the first is the original client
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Fallback to RemoteAddr (might be proxy IP)
	// Split host and port, return only host
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	// Return RemoteAddr as is if splitting fails (e.g., no port)
	return r.RemoteAddr
}

// Handlers holds dependencies for HTTP handlers.
type Handlers struct {
	Storage *storage.Storage
	Config  *config.Config
	Log     *slog.Logger
	Tmpl    *template.Template
}

// New creates a new Handlers instance.
func New(store *storage.Storage, cfg *config.Config, logger *slog.Logger, tmpl *template.Template) *Handlers {
	return &Handlers{
		Storage: store,
		Config:  cfg,
		Log:     logger.With("component", "handlers"),
		Tmpl:    tmpl,
	}
}

// --- Helper Functions ---

func httpError(w http.ResponseWriter, logger *slog.Logger, message string, err error, statusCode int) {
	logMsg := message
	if err != nil {
		logMsg = fmt.Sprintf("%s: %v", message, err)
	}
	logger.Error(logMsg)
	http.Error(w, message, statusCode)
}

func isAdmin(r *http.Request, cfg *config.Config) bool {
	key := r.Context().Value(middleware.AuthKeyContextKey)
	return cfg != nil && key == cfg.AdminKey && cfg.AdminKey != ""
}

// --- Handlers ---

// UploadHandler handles file uploads.
func (h *Handlers) UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := h.Log.With("handler", "UploadHandler")

	// Parse multipart form
	// Use MaxBytesReader to limit upload size
	maxUploadBytes := int64(h.Config.MaxUploadSizeMB) * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	err := r.ParseMultipartForm(maxUploadBytes)
	if err != nil {
		httpError(w, logger, fmt.Sprintf("Failed to parse multipart form (max size %dMB)", h.Config.MaxUploadSizeMB), err, http.StatusBadRequest)
		return
	}

	fileReader, fileHeader, err := r.FormFile("file")
	if err != nil {
		httpError(w, logger, "Failed to get file from form", err, http.StatusBadRequest)
		return
	}
	defer fileReader.Close()

	originalFilename := fileHeader.Filename
	logger.Info("Received upload request", "originalFilename", originalFilename)

	ext := filepath.Ext(originalFilename)

	// Get requested URL length
	urlLenStr := r.FormValue("urllen")
	urlLen := 8 // Default length
	if urlLenStr != "" {
		parsedLen, err := strconv.Atoi(urlLenStr)
		if err == nil {
			urlLen = parsedLen // Use provided length if valid integer
		} else {
			logger.Warn("Invalid urllen parameter received, using default", "input", urlLenStr, "error", err)
		}
	}

	// --- Read file content --- ADDED
	// Need to read the content here to calculate dimensions before saving metadata
	// Ensure fileReader is still closed via defer earlier
	contentBytes, err := io.ReadAll(fileReader)
	if err != nil {
		// Handle error reading file content before storage attempt
		httpError(w, logger, "Failed to read file content", err, http.StatusInternalServerError)
		return
	}

	// Generate unique filename with specified length
	uniqueFilename, err := h.Storage.GenerateUniqueFilename(r.Context(), ext, urlLen)
	if err != nil {
		httpError(w, logger, "Failed to generate unique filename", err, http.StatusInternalServerError)
		return
	}

	// Basic MIME type detection
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		// Fallback or read first 512 bytes if necessary, but keep it simple for now
		mimeType = "application/octet-stream"
		logger.Warn("Could not detect MIME type from extension", "extension", ext, "filename", originalFilename)
	}

	// Parse optional form values
	description := r.FormValue("description")
	message := r.FormValue("message")
	tagsStr := r.FormValue("tags")
	hiddenStr := r.FormValue("hidden")
	expiryDurationStr := r.FormValue("expiry_duration")
	panoramaStr := r.FormValue("panorama")

	// Process tags
	var tags []string
	if tagsStr != "" {
		rawTags := strings.Split(tagsStr, ",")
		for _, t := range rawTags {
			tag := strings.TrimSpace(t)
			if tag != "" {
				// Basic tag sanitization (allow alphanumeric and hyphen)
				// A more robust regex might be needed
				sanitizedTag := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
						return r
					}
					return -1 // Drop other characters
				}, strings.ToLower(tag))

				if sanitizedTag != "" {
					tags = append(tags, sanitizedTag)
				}
			}
		}
	}

	hidden := hiddenStr == "true"
	panorama := panoramaStr == "true"

	// Calculate expiry
	var expiryTime int64
	expiryDuration := h.Config.DefaultExpiryDuration
	if expiryDurationStr != "" {
		parsedDuration, err := time.ParseDuration(expiryDurationStr)
		if err != nil {
			logger.Warn("Invalid expiry duration provided, using default", "input", expiryDurationStr, "error", err)
		} else {
			expiryDuration = parsedDuration
		}
	}
	if expiryDuration > 0 {
		expiryTime = time.Now().Add(expiryDuration).Unix()
	}

	// --- Process Custom Metadata ---
	meta := make(map[string]string)
	metaPrefix := "meta_" // Define the prefix for metadata form fields
	for key, values := range r.MultipartForm.Value {
		if strings.HasPrefix(key, metaPrefix) && len(values) > 0 {
			metaKey := strings.TrimPrefix(key, metaPrefix)
			if metaKey != "" { // Ensure we have a key after trimming
				// Use the first value provided for this key
				// Consider simple sanitization if needed, e.g., template.HTMLEscapeString(values[0])
				meta[metaKey] = values[0]
				logger.Debug("Processed custom metadata field", "key", metaKey, "value", values[0])
			}
		}
	}
	// --- End Process Custom Metadata ---

	// --- Calculate Image Dimensions --- // ADDED
	var width, height int
	if strings.HasPrefix(mimeType, "image/") {
		imgConfig, _, err := image.DecodeConfig(bytes.NewReader(contentBytes))
		if err != nil {
			// Log error but don't fail the upload
			logger.Warn("Could not decode image config to get dimensions", "filename", originalFilename, "error", err)
		} else {
			width = imgConfig.Width
			height = imgConfig.Height
			logger.Debug("Calculated image dimensions", "width", width, "height", height)
		}
	}
	// --- End Calculate Image Dimensions ---

	fileInfo := file.Info{
		Name:        uniqueFilename,
		Description: description,
		Message:     message,
		Hidden:      hidden,
		Tags:        tags,
		Meta:        meta, // Assign the parsed metadata map
		MimeType:    mimeType,
		Size:        fileHeader.Size, // Original size (fileHeader.Size is fine here)
		Timestamp:   time.Now().Unix(),
		KeyExpiry:   expiryTime,
		Panorama:    panorama,
		Width:       width,  // Assign calculated width
		Height:      height, // Assign calculated height
	}

	if err := fileInfo.Validate(); err != nil {
		httpError(w, logger, fmt.Sprintf("Invalid file metadata: %v", err), nil, http.StatusBadRequest)
		return
	}

	// Store the file (passing contentBytes)
	err = h.Storage.PutFile(r.Context(), uniqueFilename, fileInfo, contentBytes)
	if err != nil {
		httpError(w, logger, "Failed to store file", err, http.StatusInternalServerError)
		return
	}

	// Construct the base URL
	baseURL := h.Config.BaseURL

	// --- Determine Response URL ---
	var responseURL string
	isText := strings.HasPrefix(fileInfo.MimeType, "text/")
	isPanorama := fileInfo.Panorama // Use the correct field name from file.Info

	if isText || isPanorama {
		// Use detail URL (path only, no key)
		// NOTE: Assumes BaseURL is correctly configured (e.g., "http://localhost:9999/")
		detailPath := fmt.Sprintf("detail/%s", uniqueFilename) // No key parameter
		responseURL = baseURL + strings.TrimPrefix(detailPath, "/")
	} else {
		// Use direct file URL (no key)
		responseURL = baseURL + strings.TrimPrefix(uniqueFilename, "/")
	}
	logger.Debug("Determined response URL", "url", responseURL, "isText", isText, "isPanorama", isPanorama)
	// --- End Determine Response URL ---

	// Define response struct
	type uploadResponse struct {
		URL string `json:"url"`
	}

	// Prepare JSON response
	resp := uploadResponse{URL: responseURL} // Use the determined URL
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		// Log the marshalling error, but maybe still return plain text URL as fallback?
		// Or return a generic server error.
		logger.Error("Failed to marshal JSON response", "error", err)
		httpError(w, logger, "Failed to create response", err, http.StatusInternalServerError)
		return
	}

	// Set headers and write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResp)
	logger.Info("File uploaded successfully", "filename", uniqueFilename, "url", responseURL) // Use determined URL
}

// FileServingHandler serves the raw file content.
func (h *Handlers) FileServingHandler(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	logger := h.Log.With("handler", "FileServingHandler", "filename", filename)

	// Validate filename format
	if !validFilenameRegex.MatchString(filename) {
		logger.Warn("Invalid filename format requested")
		http.NotFound(w, r)
		return
	}

	storedObj, err := h.Storage.GetStoredObject(r.Context(), filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			httpError(w, logger, "Failed to retrieve file", err, http.StatusInternalServerError)
		}
		return
	}

	if storedObj.Metadata.Hidden && !isAdmin(r, h.Config) {
		logger.Warn("Attempt to access hidden file without admin key")
		http.NotFound(w, r) // Treat hidden files as not found for non-admins
		return
	}

	// Set headers
	w.Header().Set("Content-Type", storedObj.Metadata.MimeType)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(storedObj.ContentGz)))
	// Add cache headers if desired
	// w.Header().Set("Cache-Control", "public, max-age=...")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(storedObj.ContentGz)
	if err != nil {
		logger.Error("Failed to write file content to response", "error", err)
	}
}

// detailPageData holds data for the detail view template.
type detailPageData struct {
	Info            file.Info
	Key             string
	IsAdmin         bool
	RenderedContent template.HTML     // Pre-rendered HTML for markdown/text
	Views           int               // Added Views
	Metadata        map[string]string // Added Metadata map
	ExpiresIn       string            // Added ExpiresIn string
	// PanoramaScript  template.JS    // REMOVED - Script is now inline in template
}

// --- Helper for human-readable duration ---
// (Could be moved to a helpers package later)
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	d = d.Round(time.Second)
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	// Only show seconds if duration is less than a minute or exactly 0
	if len(parts) == 0 || seconds > 0 && d < time.Minute {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if len(parts) == 0 {
		return "0s" // Handle zero duration
	}
	return strings.Join(parts, " ")
}

// renderDetail serves the detail page for a specific file.
func (h *Handlers) renderDetail(w http.ResponseWriter, r *http.Request, isPartial bool) {
	filename := filepath.Base(r.URL.Path)
	key := r.URL.Query().Get("key")
	// Determine admin status directly via query key for this route,
	// as AuthCheck middleware is not applied globally to detail views.
	admin := key != "" && h.Config.AdminKey != "" && key == h.Config.AdminKey

	logger := h.Log.With("handler", "renderDetail", "filename", filename, "isAdmin", admin)

	if !validFilenameRegex.MatchString(filename) {
		logger.Warn("Invalid filename format requested")
		http.NotFound(w, r)
		return
	}

	storedObj, err := h.Storage.GetStoredObject(r.Context(), filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("File not found in storage")
			http.NotFound(w, r)
		} else {
			httpError(w, logger, "Failed to retrieve file metadata", err, http.StatusInternalServerError)
		}
		return
	}

	if storedObj.Metadata.Hidden && !admin {
		logger.Warn("Attempt to access hidden file without admin key")
		http.NotFound(w, r)
		return
	}

	// --- Increment Unique View Count ---
	clientIP := getClientIP(r) // Get client IP using helper
	if err := h.Storage.IncrementViewCountUnique(r.Context(), filename, clientIP); err != nil {
		// Log the error but don't fail the request just because view count failed
		logger.Error("Failed to increment unique view count", "error", err, "clientIP", clientIP)
	}
	// --- End Increment Unique View Count ---

	var renderedContent template.HTML
	contentType := storedObj.Metadata.MimeType

	// --- Calculate ExpiresIn ---
	var expiresInStr string
	if storedObj.Metadata.KeyExpiry > 0 {
		expiryTime := time.Unix(storedObj.Metadata.KeyExpiry, 0)
		now := time.Now()
		if expiryTime.After(now) {
			duration := time.Until(expiryTime)
			// Use the new helper function
			expiresInStr = humanDuration(duration)
		} else {
			expiresInStr = "Expired"
		}
	} else {
		expiresInStr = "Never"
	}

	// --- Render content for text/markdown if applicable ---
	if strings.HasPrefix(contentType, "text/") {
		// Use the DecompressContent function from storage package
		rawContent, err := storage.DecompressContent(storedObj.ContentGz)
		if err != nil {
			httpError(w, logger, "Failed to decompress content", err, http.StatusInternalServerError)
			return
		}

		// Render if markdown or plain text (check prefix for plain text)
		if contentType == "text/markdown" || contentType == "text/x-markdown" || strings.HasPrefix(contentType, "text/plain") {
			// Use the markdown renderer, handle potential error
			htmlBytes, renderErr := markdown.Render(string(rawContent))
			if renderErr != nil {
				logger.Error("Markdown rendering failed", "error", renderErr)
				// Fallback to pre-formatted text on rendering error
				renderedContent = template.HTML("<p>Error rendering content.</p><pre>" + template.HTMLEscapeString(string(rawContent)) + "</pre>")
			} else {
				renderedContent = template.HTML(htmlBytes)
			}
		} else {
			// For other text types (e.g., text/css, text/javascript), treat as preformatted
			renderedContent = template.HTML("<pre>" + template.HTMLEscapeString(string(rawContent)) + "</pre>")
		}
	}

	// --- Panorama Script Generation REMOVED ---
	/*
		var panoramaScript template.JS = ""
		if storedObj.Metadata.Panorama {
			// ... (old script generation logic removed) ...
		}
	*/

	data := detailPageData{
		Info:            storedObj.Metadata, // file.Info struct itself
		Key:             key,
		IsAdmin:         admin,
		RenderedContent: renderedContent,
		Views:           storedObj.Metadata.Views,
		Metadata:        storedObj.Metadata.Meta, // Corrected: Use the 'Meta' field from file.Info
		ExpiresIn:       expiresInStr,
		// PanoramaScript:  panoramaScript, // REMOVED
	}

	templateName := "detail.html"
	if isPartial {
		logger.Warn("Partial rendering requested but not implemented for detail view")
		templateName = "detail.html"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.Tmpl.ExecuteTemplate(w, templateName, data); err != nil {
		httpError(w, logger, "Failed to execute detail template", err, http.StatusInternalServerError)
	}
}

// DetailViewHandler serves the HTML page for a single file.
func (h *Handlers) DetailViewHandler(w http.ResponseWriter, r *http.Request) {
	// Delegate all logic to renderDetail
	h.renderDetail(w, r, false) // isPartial = false
}

// GalleryHandler, GalleryItemsHandler, renderGallery removed - they are in gallery.go

// ThumbnailHandler serves generated thumbnails.
func (h *Handlers) ThumbnailHandler(w http.ResponseWriter, r *http.Request) {
	prefix := "/thumbnail/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	filename := filepath.Base(r.URL.Path[len(prefix):])

	logger := h.Log.With("handler", "ThumbnailHandler", "filename", filename)

	// Validate filename format
	if !validFilenameRegex.MatchString(filename) {
		logger.Warn("Invalid filename format requested for thumbnail")
		http.NotFound(w, r)
		return
	}

	storedObj, err := h.Storage.GetStoredObject(r.Context(), filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			httpError(w, logger, "Failed to retrieve file for thumbnail", err, http.StatusInternalServerError)
		}
		return
	}

	if storedObj.Metadata.Hidden && !isAdmin(r, h.Config) {
		logger.Warn("Attempt to access hidden file thumbnail without admin key")
		http.NotFound(w, r)
		return
	}

	// Check if it's an image type we can handle
	if !strings.HasPrefix(storedObj.Metadata.MimeType, "image/") {
		httpError(w, logger, "File is not an image", nil, http.StatusBadRequest)
		return
	}

	// Decompress
	decompressed, err := storage.DecompressContent(storedObj.ContentGz)
	if err != nil {
		httpError(w, logger, "Failed to decompress image for thumbnail", err, http.StatusInternalServerError)
		return
	}

	// Decode image
	img, format, err := image.Decode(bytes.NewReader(decompressed))
	if err != nil {
		httpError(w, logger, "Failed to decode image", err, http.StatusInternalServerError)
		return
	}
	logger.Debug("Decoded image for thumbnail", "format", format)

	// Generate thumbnail (e.g., 400x300 max, preserving aspect ratio)
	thumb := imaging.Thumbnail(img, 400, 300, imaging.Lanczos)

	// Encode as JPEG
	w.Header().Set("Content-Type", "image/jpeg")
	// Add cache headers
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 1 day

	err = imaging.Encode(w, thumb, imaging.JPEG, imaging.JPEGQuality(85))
	if err != nil {
		httpError(w, logger, "Failed to encode thumbnail", err, http.StatusInternalServerError)
		return
	}
}

// DeleteHandler handles file deletion.
func (h *Handlers) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := filepath.Base(r.URL.Path)
	logger := h.Log.With("handler", "DeleteHandler", "filename", filename)

	// --- Authorization Check ---
	if !isAdmin(r, h.Config) {
		logger.Warn("Unauthorized attempt to delete file")
		// Note: Middleware should already block this, but belt-and-suspenders.
		httpError(w, logger, "Forbidden", nil, http.StatusForbidden)
		return
	}
	// --- End Authorization Check ---

	// Validate filename format
	if !validFilenameRegex.MatchString(filename) {
		logger.Warn("Invalid filename format requested for deletion")
		// Return 404 or potentially 400 Bad Request? 404 seems reasonable.
		http.NotFound(w, r)
		return
	}

	err := h.Storage.DeleteFile(r.Context(), filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Already deleted or never existed - considered success for idempotent DELETE
			logger.Warn("Attempted to delete non-existent file", "error", err)
			w.WriteHeader(http.StatusOK) // Or http.StatusNoContent
		} else {
			httpError(w, logger, "Failed to delete file", err, http.StatusInternalServerError)
		}
		return
	}

	logger.Info("File deleted successfully")
	w.WriteHeader(http.StatusOK) // Or http.StatusNoContent
	// Optionally return something if not using hx-swap="outerHTML"
	// fmt.Fprint(w, "Deleted")
}

// StaticHandler serves static files.
func (h *Handlers) StaticHandler(fs http.FileSystem) http.Handler {
	return http.StripPrefix("/static/", http.FileServer(fs))
}

// --- Helper for gallery text snippet generation (kept here for DetailView, if needed) ---
// This might be better placed in the templates package or removed if DetailView doesn't need it.
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	// Find the last space within the length limit for cleaner truncation
	if idx := strings.LastIndex(s[:length], " "); idx != -1 {
		return s[:idx] + "..."
	}
	return s[:length] + "..."
}
