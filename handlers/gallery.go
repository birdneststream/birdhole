package handlers

import (
	// Added for error checking
	"fmt"
	"net/http"

	// Added for os.ErrNotExist
	// Go 1.21+ for slices.Contains
	"sort"
	"strings"
	"time"

	// Add imports for markdown, image processing etc. when needed

	"birdhole/storage"
	"birdhole/templates"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"
)

// Handlers struct and NewHandlers func removed - should be defined in handlers.go

// renderGallery handles both the full page load and the HTMX partial updates.
// It fetches, filters, sorts, and prepares data for the gallery templates.
func (h *Handlers) renderGallery(w http.ResponseWriter, r *http.Request, isPartial bool) {
	ctx := r.Context()
	log := h.Log.With("handler", "renderGallery")

	// Determine the correct template name/block based on the request context
	templateName := "gallery.html" // Default: full page

	// Check the source of the request - was it GalleryItemsHandler or partial GalleryHandler?
	// Distinguish between rendering just items vs rendering nav+items.
	// We use the `isPartial` flag and potentially check the request path or a specific param if needed.
	// Let's redefine isPartial: true means render a block, false means render the full page.
	// We need a way to know WHICH block to render.

	// Simplification: Let's assume GalleryItemsHandler always renders items,
	// and GalleryHandler with partial=true renders the content block.

	// Check if the request path is for items specifically
	if strings.HasSuffix(r.URL.Path, "/items") {
		templateName = "gallery_items.html" // Target the items block directly
		log = log.With("render_mode", "items_only")
	} else if isPartial { // This means GalleryHandler was called with partial=true
		templateName = "gallery-content" // Target the content block defined in gallery.html
		log = log.With("render_mode", "content_block")
	} else {
		log = log.With("render_mode", "full_page")
	}

	// --- Authentication/Authorization ---
	// For the public gallery route, admin status for display purposes
	// is determined directly by the query key, as AuthCheck middleware isn't applied.
	queryKey := r.URL.Query().Get("key")
	isAdmin := queryKey != "" && h.Config.AdminKey != "" && queryKey == h.Config.AdminKey

	// --- Fetch All File Metadata ---
	allFilesInfo, err := h.Storage.GetAllFilesInfo(ctx)
	if err != nil {
		log.Error("Failed to get all files info", "error", err)
		// Render error message suitable for HTMX swap
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div class="error-message">Error loading files. Please try again later.</div>`) // Simple error feedback
		return
	}
	log.Debug("Total files fetched from storage", "count", len(allFilesInfo))
	// --- End Fetch ---

	// --- Filtering and Sorting ---
	activeTag := r.URL.Query().Get("tag")
	sortOrder := r.URL.Query().Get("sort")  // Expected: "new" or "old"
	activeMime := r.URL.Query().Get("mime") // ADDED: Get mime type filter
	searchQuery := r.URL.Query().Get("q")   // ADDED: Get search query

	log.Debug("Gallery view parameters", "isAdmin", isAdmin, "activeTag", activeTag, "sortOrder", sortOrder, "activeMime", activeMime, "searchQuery", searchQuery) // ADDED searchQuery

	// Use FileInfoWrapper to include Snippet
	var filteredFiles []templates.FileInfoWrapper // Changed type here
	uniqueTags := make(map[string]struct{})       // Using map as a set for unique tags
	uniqueMimeTypes := make(map[string]struct{})  // ADDED: Map for unique mime types

	for _, fileInfo := range allFilesInfo {
		log.Debug("Processing file for gallery", "filename", fileInfo.Name, "hidden", fileInfo.Hidden, "tags", fileInfo.Tags)

		// Collect all unique tags and mime types from accessible files
		isVisible := !fileInfo.Hidden || isAdmin
		if isVisible {
			for _, tag := range fileInfo.Tags {
				if tag != "" {
					uniqueTags[strings.TrimSpace(tag)] = struct{}{} // Trim spaces from tags
				}
			}
			// ADDED: Collect unique mime types
			if fileInfo.MimeType != "" {
				uniqueMimeTypes[fileInfo.MimeType] = struct{}{}
			}
		}

		// Apply Filters:
		// 1. Visibility Filter (already checked by isVisible)
		if !isVisible {
			continue // Skip hidden files if not admin
		}

		// 2. Tag Filter (Apply only if activeTag is provided)
		if activeTag != "" {
			// *** FIXED LOGIC HERE ***
			tagFound := false
			for _, tag := range fileInfo.Tags {
				if strings.TrimSpace(tag) == activeTag {
					tagFound = true
					break
				}
			}
			if !tagFound {
				log.Debug("Skipping file due to tag mismatch", "filename", fileInfo.Name, "activeTag", activeTag)
				continue // Skip if tag filter is active and file doesn't have the tag
			}
		}

		// 3. MIME Type Filter (Apply only if activeMime is provided)
		if activeMime != "" && fileInfo.MimeType != activeMime {
			log.Debug("Skipping file due to MIME type mismatch", "filename", fileInfo.Name, "activeMime", activeMime, "fileMime", fileInfo.MimeType)
			continue
		}

		// 4. Search Query Filter (Apply only if searchQuery is provided) - ADDED
		if searchQuery != "" {
			lcQuery := strings.ToLower(searchQuery)
			nameMatch := strings.Contains(strings.ToLower(fileInfo.Name), lcQuery)
			descMatch := strings.Contains(strings.ToLower(fileInfo.Description), lcQuery)
			if !nameMatch && !descMatch {
				log.Debug("Skipping file due to search query mismatch", "filename", fileInfo.Name, "searchQuery", searchQuery)
				continue
			}
		}

		// Create FileInfoWrapper
		wrapper := templates.FileInfoWrapper{
			Info:    fileInfo, // Embed the original file.Info
			Key:     queryKey, // Pass key for potential use in item template
			IsAdmin: isAdmin,
		}

		// Generate snippet for text files
		if strings.HasPrefix(fileInfo.MimeType, "text/") {
			// Need to fetch the full object to get content
			storedObj, getErr := h.Storage.GetStoredObject(ctx, fileInfo.Name)
			if getErr != nil {
				log.Error("Failed to get stored object for snippet generation", "filename", fileInfo.Name, "error", getErr)
				// Decide how to handle: skip snippet, show error, etc.
				wrapper.Snippet = "(Error loading content)"
			} else {
				rawContent, decompErr := storage.DecompressContent(storedObj.ContentGz)
				if decompErr != nil {
					log.Error("Failed to decompress content for snippet generation", "filename", fileInfo.Name, "error", decompErr)
					wrapper.Snippet = "(Error reading content)"
				} else {
					// Use the truncateString helper (already defined in handlers.go)
					wrapper.Snippet = truncateString(string(rawContent), 150) // Truncate to 150 chars
					if wrapper.Snippet == "" {
						wrapper.Snippet = "(Empty text file)" // Handle empty content after truncation
					}
				}
			}
		}

		// If the file passed all filters, add it to the list
		log.Debug("Adding file to filtered list", "filename", fileInfo.Name)
		filteredFiles = append(filteredFiles, wrapper) // Append the wrapper
	}
	log.Debug("Finished filtering files", "filtered_count", len(filteredFiles))

	// Apply Sorting
	if sortOrder == "old" {
		sort.SliceStable(filteredFiles, func(i, j int) bool {
			return filteredFiles[i].Info.Timestamp < filteredFiles[j].Info.Timestamp
		})
		log.Debug("Sorted files by oldest")
	} else { // Default to "new" (including invalid sortOrder values)
		sort.SliceStable(filteredFiles, func(i, j int) bool {
			return filteredFiles[i].Info.Timestamp > filteredFiles[j].Info.Timestamp
		})
		if sortOrder != "" && sortOrder != "new" {
			log.Warn("Invalid sort order received, defaulting to newest", "sortOrder", sortOrder)
		}
		log.Debug("Sorted files by newest (default)")
	}
	// --- End Filtering and Sorting ---

	// --- Prepare Template Data ---
	// Convert unique tags map to sorted list
	tagList := make([]string, 0, len(uniqueTags))
	for tag := range uniqueTags {
		tagList = append(tagList, tag)
	}
	sort.Strings(tagList) // Keep tag list sorted for consistent display

	// Convert unique mime types map to sorted list - ADDED
	mimeList := make([]string, 0, len(uniqueMimeTypes))
	for mime := range uniqueMimeTypes {
		mimeList = append(mimeList, mime)
	}
	sort.Strings(mimeList) // Keep mime list sorted

	data := map[string]interface{}{
		"Files":           filteredFiles,
		"UniqueTags":      tagList,
		"ActiveTag":       activeTag,
		"UniqueMimeTypes": mimeList,   // ADDED
		"ActiveMime":      activeMime, // ADDED
		"SortOrder":       sortOrder,
		"SearchQuery":     searchQuery, // ADDED
		"CurrentKey":      queryKey,    // Pass original query key for constructing links/URLs in template
		"IsAdmin":         isAdmin,
		"RefreshParam":    fmt.Sprintf("?ts=%d", time.Now().UnixNano()), // Basic cache buster for polling
	}
	// --- End Template Data ---

	// --- Render Template ---
	log.Info("Rendering gallery template", "template_target", templateName, "item_count", len(filteredFiles))
	err = h.Tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		// Log the error, but avoid writing a second HTTP error response if one was already sent (e.g., 500 earlier)
		log.Error("Failed to execute gallery template", "template", templateName, "error", err)
		// Check if headers were already written before trying to send another error
		if _, ok := w.Header()["Content-Type"]; !ok {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
	// --- End Render ---
}

// GalleryHandler serves the full gallery page HTML or just the content block.
func (h *Handlers) GalleryHandler(w http.ResponseWriter, r *http.Request) {
	// Check if it's a partial request (e.g., from polling)
	isPartialContent := r.URL.Query().Get("partial") == "true"

	if isPartialContent {
		// If partial, render only the content block
		// We still need to run renderGallery to get the data
		h.renderGallery(w, r, true) // Pass true to indicate partial rendering for content
	} else {
		// Otherwise, render the full page
		h.renderGallery(w, r, false) // Pass false for full page render
	}
}

// GalleryItemsHandler serves the partial HTML fragment containing just the gallery items.
// This is typically triggered by HTMX for tag filtering, sorting, or auto-refresh.
func (h *Handlers) GalleryItemsHandler(w http.ResponseWriter, r *http.Request) {
	// This handler always renders just the items template block.
	// We still call renderGallery to fetch and filter data,
	// but we will explicitly execute the items template.
	// log := h.Log.With("handler", "GalleryItemsHandler") // REMOVED unused variable

	// Fetch and prepare data using a simplified call or dedicated function?
	// For now, reuse renderGallery but ignore its template execution.
	// We need the data map it prepares.

	// PROBLEM: renderGallery *executes* a template. We need the data *before* execution.
	// Let's refactor renderGallery to separate data prep from execution.

	// TODO: Refactor renderGallery to return data map + chosen template name?
	// Temporary workaround: Call renderGallery and hope it executes the right block
	// based on the path check inside it.
	// This relies on renderGallery correctly identifying templateName = "gallery_items.html"
	h.renderGallery(w, r, true)

	// --- REFACTOR NEEDED ---
	// Ideal structure:
	// 1. Call a function like prepareGalleryData(r) -> (data, error)
	// 2. Check error
	// 3. h.Tmpl.ExecuteTemplate(w, "gallery_items.html", data)
}

// --- Placeholder Handlers Removed ---
