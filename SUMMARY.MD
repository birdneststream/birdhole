# Birdhole (Simplified) - Development Instructions

## 1. Goal

Create a simplified, self-hosted file sharing service inspired by the original Birdhole. Focus on core functionality, ease of maintenance, and a rich user experience powered by HTMX and vanilla CSS.

## 2. Core Requirements

*   **File Upload:** Allow authenticated users to upload files with optional metadata (description, tags, hidden status, expiry, panorama flag).
*   **File Serving:** Provide direct URL access to uploaded, non-hidden files.
*   **Rich Gallery:** Display a list or grid of non-hidden uploaded files with appropriate previews (thumbnails, snippets, players), filtering by tag, and sorting. Gallery should auto-refresh.
*   **Detail View:** Provide a dedicated view for individual files with larger previews and rendered content (e.g., Markdown).
*   **Panorama View:** Support interactive viewing of panorama images.
*   **File Deletion:** Allow authenticated admins to delete files.
*   **Authentication:** Simple, key-based authentication for uploads and administrative actions (gallery viewing optional).
*   **Configuration:** Load settings from a `config.toml` file.
*   **Rate Limiting:** Handled externally by Cloudflare (application does not implement its own).
*   **Deployment Context:** Assumed to be hosted behind a reverse proxy like Cloudflare.

## 3. Technology Stack

*   **Backend:** Go (latest stable)
*   **Frontend:** HTML5, Vanilla CSS, HTMX
*   **Storage:** Bitcask (embedded key/value store)
*   **Compression:** Go standard library `compress/gzip` (Level 9)
*   **Configuration Parsing:** TOML (e.g., `github.com/BurntSushi/toml`)
*   **Markdown Parsing:** Goldmark (e.g., `github.com/yuin/goldmark`)
*   **HTML Sanitization:** Bluemonday (e.g., `github.com/microcosm-cc/bluemonday`)
*   **Image Processing:** Go standard image libraries + `github.com/disintegration/imaging`
*   **Panorama Viewing:** A JavaScript library (e.g., Photo Sphere Viewer - self-hosted or CDN)

## 4. Key Simplifications & Trade-offs

*   **Backend Simplification:**
    *   Store file metadata *and* gzipped content together within Bitcask.
    *   Remove view counting and expiry extension based on views.
    *   Basic file validation (type, size).
    *   *Omit application-level rate limiting*, relying on Cloudflare.
*   **Frontend Approach:**
    *   Rely primarily on standard HTML, CSS, and HTMX capabilities.
    *   Use URL query parameters for gallery state (filters, sorting) where feasible.
    *   *Minimal additional JavaScript* is required (specifically for the panorama viewer library).
    *   *Retain rich previews* in the gallery and detail views, adding some frontend complexity back compared to a purely minimal approach.
    *   *Retain panorama viewer* functionality.

## 5. Proposed Package Structure

*   `main`: Entry point, server setup, basic routing.
*   `config`: Load configuration from `config.toml` file.
*   `storage`: Interface with Bitcask for storing/retrieving metadata and gzipped content. Handles compression/decompression.
*   `handlers`: HTTP request handlers for uploads, file serving, gallery, detail view, deletion.
*   `templates`: Go `html/template` definitions and helpers.
*   `middleware`: Basic essential middleware (logging, recovery, auth checks, security headers, client IP extraction).
*   `file`: Defines the core `FileInfo` metadata struct.
*   `markdown`: Wrapper for Markdown parsing and sanitization.

### `file.FileInfo` Definition (`file/file.go`)

```go
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
	Name        string            `json:"name"`                  // Unique filename (e.g., randomname.ext)
	Description string            `json:"description,omitempty"` // User-provided description
	Message     string            `json:"message,omitempty"`     // Optional user-provided message
	Hidden      bool              `json:"hidden"`                  // Flag to hide from public gallery view
	Tags        []string          `json:"tags,omitempty"`        // User-provided tags
	Meta        map[string]string `json:"meta,omitempty"`        // Arbitrary user-provided key-value metadata (ensure keys/values are sanitized)
	MimeType    string            `json:"mime_type"`             // Detected MIME type of the file
	Size        int64             `json:"size"`                  // Original file size in bytes (before compression)
	Timestamp   int64             `json:"timestamp"`             // Unix timestamp of upload time
	KeyExpiry   int64             `json:"key_expiry"`            // Unix timestamp when the file should expire
	Views       int               `json:"views"`                 // View count (NOTE: Simplified version removes view increment logic, but field kept for potential future use/data compatibility)
	Width       int               `json:"width,omitempty"`       // Image width (if applicable)
	Height      int               `json:"height,omitempty"`      // Image height (if applicable)
	Hash        string            `json:"hash,omitempty"`        // Optional file hash (consider adding SHA256 calculation on upload)
	ProcessedAt int64             `json:"processed_at,omitempty"`// Optional timestamp for when processing (like thumbnailing) finished
	Panorama    bool              `json:"panorama,omitempty"`    // Panorama flag for detail view
}


// --- Include necessary helper methods from the original file/file.go if needed ---
// Example: GetExtension, IsExpired, Validate etc. might still be useful,
// but FormatSize might be less relevant if displaying sizes differently.

// GetExtension returns the file extension
func (i *Info) GetExtension() string {
	return strings.ToLower(filepath.Ext(i.Name))
}

// IsExpired checks if the file has expired based on KeyExpiry
func (i *Info) IsExpired() bool {
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
	// Add other necessary checks (e.g., timestamp > 0, expiry > timestamp)
	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errors, ", "))
	}
	return nil
}
```

## 6. Storage Layer (`storage` package)

*   **Backend:** Use `git.mills.io/prologic/bitcask`.
*   **Schema:**
    *   Key: Unique generated filename (e.g., `randomname.ext`).
    *   Value: JSON Marshaled `StoredObject` struct (defined below).

*   **`storage.StoredObject` Definition (`storage/storage.go`)**

    This is the structure that will actually be marshaled into JSON and stored as the *value* in the Bitcask database. It embeds the `FileInfo` struct.

    ```go
    package storage

    import (
    	"birdhole/file" // Assuming 'file' package is in 'birdhole/file'
    )

    // StoredObject is the structure stored as the value in Bitcask.
    // It includes the metadata and the compressed file content.
    type StoredObject struct {
    	// Embeds all fields from file.Info (Name, Description, Tags, KeyExpiry, etc.)
    	Info file.FileInfo `json:"info"`

    	// Stores the file content after gzip compression (Level 9)
    	GzippedContent []byte `json:"gzipped_content"`
    }
    ```

*   **Core Functions:**
    *   `NewStorage(dbPath string) (*Storage, error)`: Initialize Bitcask connection.
    *   `PutFile(ctx context.Context, info file.FileInfo, content io.Reader) error`:\
        *   Reads content from the reader.
        *   Compresses content using `gzip.NewWriterLevel` (Level 9).
        *   Creates `StoredObject` with metadata and gzipped bytes.
        *   Marshals `StoredObject` to JSON.
        *   Stores in Bitcask using `info.Name` as the key.
        *   *Ensure critical errors during storage are logged.*
    *   `GetStoredObject(ctx context.Context, filename string) (*StoredObject, error)`: Retrieves the raw `StoredObject` JSON from Bitcask and unmarshals it. Returns "not found" error if missing.
    *   `GetAllFilesInfo(ctx context.Context) ([]file.FileInfo, error)`: Iterates through all keys in Bitcask, retrieves each `StoredObject`, unmarshals it, and returns a slice containing *only* the `FileInfo` part for each entry. Skips/logs entries that fail to unmarshal.
    *   `DeleteFile(ctx context.Context, filename string) error`: Deletes the key from Bitcask. *Ensure critical errors are logged.*
    *   `GenerateUniqueFilename(ctx context.Context, extension string) (string, error)`: Generates a short, random, unique base32 filename, checking for collisions in Bitcask. *Ensure generated name is filesystem-safe (base32 helps).*
    *   `Close() error`: Closes the Bitcask DB.
*   **Expiry:** Implement a background goroutine (started by `NewStorage` or `main`) that periodically calls a `CleanupExpired(ctx context.Context)` method. This method uses `GetAllFilesInfo`, checks `Info.KeyExpiry` against the current time, and calls `DeleteFile` for expired items.

## 7. Handlers & Endpoints (`handlers` package, routed in `main`)

*   **`POST /upload` (Upload Handler):**
    *   Protected by upload auth key middleware.
    *   Parses `multipart/form-data` (`file`, `description`, `tags` [comma-separated], `hidden` [boolean], `expiry_duration` [optional string like "7d", "24h"], `panorama` [boolean]).
    *   *Sanitize `description` and `tags` input (e.g., using `html.EscapeString` or similar basic sanitization).* 
    *   Validates file type/size based on simple rules (e.g., allow common image/text types, configurable max size).
    *   Generates a unique filename using `storage.GenerateUniqueFilename`.
    *   Creates `file.FileInfo` struct: populates metadata, calculates final `KeyExpiry` based on input or default from config.
    *   Calls `storage.PutFile` with the `FileInfo` and the file content reader.
    *   On success: Return 200 OK with the direct file URL in the response body (plain text).
    *   On error: Return appropriate 4xx/5xx status code with a plain text error message in the response body.
*   **`GET /{filename}` (File Serving Handler):**
    *   Extracts `filename`.
    *   Calls `storage.GetStoredObject` to get the combined data.
    *   If not found, return 404.
    *   If `StoredObject.Info.Hidden` is true, return 404 (or 403 Forbidden).
    *   Set `Content-Type` header from `StoredObject.Info.MimeType`.
    *   Set `Content-Encoding: gzip` header.
    *   Write the `StoredObject.GzippedContent` bytes directly to the response body.
*   **`GET /detail/{filename}` (Detail View Handler - NEW):**
    *   Protected by gallery auth key middleware.
    *   Calls `storage.GetStoredObject`. Handle not found / hidden errors.
    *   Decompress `GzippedContent` using `gzip.Reader`.
    *   If text/markdown, process content:
        *   Use `goldmark` to convert Markdown to HTML.
        *   Use `bluemonday` (with appropriate policy) to sanitize the generated HTML.
        *   Pass the resulting safe `template.HTML` to the template.
    *   Pass `FileInfo` and potentially the raw (decompressed) content or processed HTML to the `detail.html` template.
    *   Render the `detail.html` template.
    *   *If errors occur, render a simple error message within the detail HTML structure.*
*   **`GET /gallery` (Gallery Handler):**
    *   Protected by gallery auth key middleware (check `?key=...`).
    *   Calls `storage.GetAllFilesInfo` to get metadata for all files.
    *   Filters out hidden files unless user is admin (check admin key via `?key=...`).
    *   Applies optional tag filtering (`?tag=...`) in Go.
    *   Applies optional sorting (`?sort=new` or `?sort=old`) in Go.
    *   *Generate text snippets server-side for text files to be included in the FileInfo data passed to the template? (Alternative: Client-side fetch/render for snippets).* Decide on approach.
    *   Renders `gallery.html` template, passing the filtered/sorted `[]file.FileInfo`, the current key, active filters/sort order, and a list of unique tags.
    *   *If errors occur (e.g., cannot fetch files), render a simple error message within the main HTML structure.*
*   **`GET /gallery/items` (Gallery Items Partial Handler):**
    *   *Purpose:* Handles HTMX requests for updating the gallery grid and tag list.
    *   Protected by gallery auth key middleware.
    *   Essentially repeats the data fetching and filtering logic of `GET /gallery` based on query parameters (`key`, `tag`, `sort`).
    *   *Generate text snippets if needed for previews.*
    *   Renders *only* the gallery items partial template (`gallery_items.html`) and returns the HTML fragment.
    *   *If errors occur, return an HTML fragment with an error message suitable for display within the gallery grid container.*
*   **`GET /thumbnail/{filename}` (Thumbnail Handler):**
    *   Protected by gallery auth key middleware.
    *   Calls `storage.GetStoredObject`. Handle not found / hidden errors.
    *   Check `Info.MimeType`. If not an image type, return 404 or a default icon.
    *   Create a `gzip.Reader` from `StoredObject.GzippedContent`.
    *   Decode the image from the gzip reader.
    *   Generate a thumbnail (e.g., 400x300 JPEG) using `disintegration/imaging`.
    *   Set `Content-Type: image/jpeg`.
    *   Encode and write the thumbnail JPEG data to the response.
    *   *Note: On-demand thumbnail generation is simpler but may impact performance for large images/high traffic.*
*   **`DELETE /{filename}` (Delete Handler):**
    *   Protected by admin auth key middleware (check `?key=...`).
    *   Calls `storage.DeleteFile`.
    *   On success: Return 200 OK (potentially no content if called via HTMX, or redirect if direct browser request).
    *   On error: Return appropriate 4xx/5xx status code with a plain text error message.
*   **`GET /static/{filepath}` (Static Handler):**
    *   Serves files (CSS, JS libraries like HTMX, Panorama Viewer) from a `./static` directory.

## 8. Frontend (`templates` package + `./static`)

*   **`style.css`:** Minimal, clean vanilla CSS for basic layout and styling of the gallery, previews, and detail view.
*   **Go Templates (`html/template`):**
    *   **`gallery.html`:**
        *   Basic HTML structure, links `style.css` and `htmx.min.js`.
        *   Header/Title.
        *   **Filtering/Sorting UI:** Implement a cleaner UI than the original buttons. Consider a `<select>` dropdown for sort order. Tag links remain the primary way to filter by tag. Ensure UI reflects the current state (selected tag/sort). Trigger HTMX `GET` requests to `/gallery/items` on change, updating the URL via `hx-push-url`.
        *   **Tag List:** Display available tags as links: `<a hx-get="/gallery/items?key=...&tag={{.}}" hx-target="#gallery-items" hx-push-url="true">#tag</a>`.
        *   **Gallery Container:** `<div id="gallery-items" class="htmx-indicator" hx-get="/gallery/items?key=..." hx-trigger="every 10s"> Loading... {{ template "gallery_items.html" . }} </div>` (Loads initial items, includes basic loading indicator, and sets up auto-refresh every 10 seconds).
    *   **`gallery_items.html`:** (Can be defined within `gallery.html` using `{{define "items"}}...{{end}}` or separate)
        *   Receives the filtered/sorted `[]file.FileInfo`.
        *   *Check if files slice is empty. If so, display a "No files found." message.*
        *   Iterates through the files.
        *   **Previews:** For each file, display an appropriate preview:
            *   Image: `<img src="/thumbnail/{{.Name}}?key=..." loading="lazy">`
            *   Audio: Show an icon. Clicking links to `/detail/{filename}`.
            *   Video: `<video muted loop autoplay src="/{filename}" style="max-width:100%; max-height:100%; object-fit: cover;"></video>` (Ensure proper styling for grid). Clicking links to `/detail/{filename}`.
            *   Text: Display a server-generated snippet (e.g., `{{ .Snippet }}`).
        *   Link the entire item (or relevant parts) to `/detail/{{.Name}}?key=...`.
        *   If admin: Include a delete button (`<button hx-delete="/{{.Name}}?key=..." hx-target="closest div" hx-swap="outerHTML">Delete</button>`).
    *   **`detail.html` (NEW):**
        *   Receives `FileInfo` and processed content/preview data from the `/detail/{filename}` handler.
        *   Displays file metadata (description, tags, timestamp, etc.).
        *   Displays appropriate preview:
            *   Image: `<img src="/{filename}">`
            *   Audio: `<audio controls src="/{filename}"></audio>`
            *   Video: `<video controls src="/{filename}"></video>`
            *   Text/Markdown: Render the sanitized HTML provided by the handler `{{ .RenderedContent }}`.
            *   Panorama: Include the necessary HTML container (`<div id="viewer"></div>`) and JS initialization script for the panorama library (e.g., Photo Sphere Viewer), using `/{filename}` as the source. Ensure the library JS/CSS are loaded.
    *   **Template Helpers:** Basic helpers for formatting dates, maybe file sizes.

## 9. Configuration (`config` package)

Load configuration from `config.toml` file (e.g., located at `./config.toml`). Use a library like `github.com/BurntSushi/toml` to parse.

Required keys in `config.toml`:
*   `Port` (string, e.g., "8080")
*   `ListenAddr` (string, e.g., "0.0.0.0")
*   `DefaultExpiry` (string, e.g., "24h") - *Ensure parsing supports units like 'h', 'd'.*
*   `BitcaskPath` (string, e.g., "./birdhole.db")
*   `UploadKey` (string, Required secret key) - *Use strong, random secrets.*
*   `GalleryKey` (string, Optional key for viewing gallery) - *Use strong, random secrets.*
*   `AdminKey` (string, Required secret key for deletion) - *Use strong, random secrets.*
*   `MaxUploadSizeMB` (integer, e.g., 100)

*Provide sensible defaults in code if the config file is missing or keys are absent (e.g., PORT="8080", DefaultExpiry="24h", MaxUploadSizeMB=100). Fail explicitly if required keys like UploadKey or AdminKey are missing.*

## 10. Middleware (`middleware` package)

*   Implement basic logging middleware (log request start/end, status code). *Ensure critical errors within middleware are logged.*
    *   *Client IP Address:* Ensure logging correctly identifies the original client IP address by checking headers like `CF-Connecting-IP` or `X-Forwarded-For`, as `r.RemoteAddr` will likely be a Cloudflare IP.
*   Implement recovery middleware (catch panics, log them, return 500). *Ensure panic details are logged.*
*   Implement simple key auth middleware (check `X-Auth-Token` for upload, `?key=` query param for gallery/admin).
*   *Rate Limiting:* Note: Application-level rate limiting is omitted. It is expected to be handled by the Cloudflare layer.
*   Implement security headers middleware (CSP, HSTS, etc.). *Ensure the Content-Security-Policy allows necessary sources for HTMX, the panorama viewer library (if CDN), and potentially inline styles/scripts if absolutely needed, although minimizing inline is preferred.*

---
*Follow these instructions to build the simplified Birdhole application.*
