package handlers

import (
	// Added for error checking

	"errors"
	"fmt"
	"net/http"
	"strconv"

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

// var ErrInvalidAccessKey = errors.New("invalid access key") // REMOVED - Defined elsewhere

// Handlers struct and NewHandlers func removed - should be defined in handlers.go

// prepareGalleryData fetches, filters, sorts, and prepares data for the gallery templates.
// It does NOT handle template execution or response writing.
func (h *Handlers) prepareGalleryData(r *http.Request) (map[string]interface{}, error) {
	ctx := r.Context()
	log := h.Log.With("function", "prepareGalleryData")

	// --- Access Control Check ---
	queryKey := r.URL.Query().Get("key")
	// Use GalleryKey for gallery access control, but also allow AdminKey
	if h.Config.GalleryKey != "" { // Check if a gallery key is required
		// Deny access ONLY if GalleryKey is required AND the provided key matches neither GalleryKey nor AdminKey
		if queryKey != h.Config.GalleryKey && queryKey != h.Config.AdminKey {
			log.Warn("Invalid gallery access key provided", "provided_key", queryKey)
			return nil, ErrInvalidAccessKey // Return specific error
		}
	}
	// --- End Access Control Check ---

	// --- Authentication/Authorization (for admin features *inside* gallery) ---
	// This uses AdminKey, separate from gallery access.
	// queryKey already fetched above
	isAdmin := queryKey != "" && h.Config.AdminKey != "" && queryKey == h.Config.AdminKey

	// --- Fetch All File Metadata ---
	allFilesInfo, err := h.Storage.GetAllFilesInfo(ctx)
	if err != nil {
		log.Error("Failed to get all files info", "error", err)
		// Return a generic error; the caller will handle the HTTP response
		return nil, fmt.Errorf("failed to retrieve file information")
	}
	log.Debug("Total files fetched from storage", "count", len(allFilesInfo))
	// --- End Fetch ---

	// --- Filtering and Sorting Parameters ---
	queryValues := r.URL.Query()
	activeTag := queryValues.Get("tag")
	sortOrder := queryValues.Get("sort")
	searchQuery := queryValues.Get("q")
	activeShowMimes := queryValues["show_type"] // Get slice directly

	// Convert activeShowMimes to a map for faster lookup if specific types are requested.
	showMimesMap := make(map[string]struct{}, len(activeShowMimes))
	// If activeShowMimes is empty or nil, it means SHOW ALL types.
	// If it's not empty, it means ONLY show the types listed.
	showOnlySpecific := len(activeShowMimes) > 0
	if showOnlySpecific {
		for _, mime := range activeShowMimes {
			if mime != "" {
				showMimesMap[mime] = struct{}{}
			}
		}
	}

	log.Debug("Gallery view parameters",
		"isAdmin", isAdmin,
		"activeTag", activeTag,
		"sortOrder", sortOrder,
		"searchQuery", searchQuery,
		"showMimes", activeShowMimes,
		"showOnlySpecific", showOnlySpecific,
	)

	// --- Filtering Logic ---
	var filteredFiles []templates.FileInfoWrapper
	uniqueTags := make(map[string]struct{})
	uniqueMimeTypes := make(map[string]struct{}) // Still collect all unique types for UI

	for _, fileInfo := range allFilesInfo {
		// Time-based filter: Only show files younger than 24 hours, unless an admin is viewing.
		isRecent := time.Unix(fileInfo.Timestamp, 0).After(time.Now().Add(-24 * time.Hour))
		if !isRecent && !isAdmin {
			continue
		}

		isVisible := !fileInfo.Hidden || isAdmin
		if isVisible {
			// Collect unique tags and mime types from all visible files for the UI controls
			for _, tag := range fileInfo.Tags {
				if tag != "" {
					uniqueTags[strings.TrimSpace(tag)] = struct{}{}
				}
			}
			if fileInfo.MimeType != "" {
				uniqueMimeTypes[fileInfo.MimeType] = struct{}{}
			}
		}

		// Apply visibility filter (admin override)
		if !isVisible {
			continue
		}

		// Apply tag filter
		if activeTag != "" {
			tagFound := false
			for _, tag := range fileInfo.Tags {
				if strings.TrimSpace(tag) == activeTag {
					tagFound = true
					break
				}
			}
			if !tagFound {
				continue
			}
		}

		// Apply search query filter
		if searchQuery != "" {
			lcQuery := strings.ToLower(searchQuery)
			nameMatch := strings.Contains(strings.ToLower(fileInfo.Name), lcQuery)
			descMatch := strings.Contains(strings.ToLower(fileInfo.Description), lcQuery)
			if !nameMatch && !descMatch {
				continue
			}
		}

		// Apply MIME type filtering (Show Only Specific)
		fileMime := fileInfo.MimeType

		// If we are showing only specific types (showOnlySpecific is true),
		// check if this file's type is in the show list.
		if showOnlySpecific {
			_, showThisType := showMimesMap[fileMime]
			if !showThisType {
				continue // Skip if not in the explicit show list
			}
		}
		// If showOnlySpecific is false (meaning activeShowMimes was empty),
		// we show all types. No check needed.

		// If the file passed all filters, prepare and add it
		wrapper := templates.FileInfoWrapper{
			Info:    fileInfo,
			Key:     queryKey,
			IsAdmin: isAdmin,
		}

		// Generate snippet for text files
		if strings.HasPrefix(fileInfo.MimeType, "text/") {
			storedObj, getErr := h.Storage.GetStoredObject(ctx, fileInfo.Name)
			if getErr != nil {
				log.Error("Failed to get stored object for snippet generation", "filename", fileInfo.Name, "error", getErr)
				wrapper.Snippet = "(Error loading content)"
			} else {
				rawContent, decompErr := storage.DecompressContent(storedObj.ContentGz)
				if decompErr != nil {
					log.Error("Failed to decompress content for snippet generation", "filename", fileInfo.Name, "error", decompErr)
					wrapper.Snippet = "(Error reading content)"
				} else {
					wrapper.Snippet = truncateString(string(rawContent), 300)
					if wrapper.Snippet == "" {
						wrapper.Snippet = "(Empty text file)"
					}
				}
			}
		}

		filteredFiles = append(filteredFiles, wrapper)
	}
	log.Debug("Finished filtering files", "filtered_count", len(filteredFiles))

	// --- Sorting ---
	if sortOrder == "old" {
		sort.SliceStable(filteredFiles, func(i, j int) bool {
			return filteredFiles[i].Info.Timestamp < filteredFiles[j].Info.Timestamp
		})
		log.Debug("Sorted files by oldest")
	} else {
		// Default to newest if sortOrder is empty or invalid
		sort.SliceStable(filteredFiles, func(i, j int) bool {
			return filteredFiles[i].Info.Timestamp > filteredFiles[j].Info.Timestamp
		})
		if sortOrder != "" && sortOrder != "new" {
			log.Warn("Invalid sort order received, defaulting to newest", "sortOrder", sortOrder)
		}
		log.Debug("Sorted files by newest (default)")
	}
	// --- End Filtering and Sorting ---

	// --- Prepare Template Data Map ---
	tagList := make([]string, 0, len(uniqueTags))
	for tag := range uniqueTags {
		tagList = append(tagList, tag)
	}
	sort.Strings(tagList)

	mimeList := make([]string, 0, len(uniqueMimeTypes))
	for mime := range uniqueMimeTypes {
		mimeList = append(mimeList, mime)
	}
	sort.Strings(mimeList)

	data := map[string]interface{}{
		"Files":           filteredFiles,
		"UniqueTags":      tagList,
		"ActiveTag":       activeTag,
		"UniqueMimeTypes": mimeList,        // Still needed for UI generation
		"ActiveShowMimes": activeShowMimes, // Pass active show types to template
		"SortOrder":       sortOrder,
		"SearchQuery":     searchQuery,
		"CurrentKey":      queryKey,
		"IsAdmin":         isAdmin,
		"RefreshParam":    fmt.Sprintf("?ts=%d", time.Now().UnixNano()), // Still useful for cache busting if needed
	}
	// --- End Template Data ---

	return data, nil // Return the prepared data and no error
}

// LoadMoreItemsHandler handles pagination for gallery items
func (h *Handlers) LoadMoreItemsHandler(w http.ResponseWriter, r *http.Request) {
	log := h.Log.With("handler", "LoadMoreItemsHandler")
	
	// Get gallery data
	data, err := h.prepareGalleryData(r)
	if err != nil {
		if errors.Is(err, ErrInvalidAccessKey) {
			http.NotFound(w, r)
		} else {
			log.Error("Failed to prepare gallery data", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="error-message">Error loading more items.</div>`)
		}
		return
	}
	
	// Get offset from query params
	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if offsetStr != "" {
		if parsedOffset, parseErr := strconv.Atoi(offsetStr); parseErr == nil {
			offset = parsedOffset
		}
	}
	
	files, ok := data["Files"].([]templates.FileInfoWrapper)
	if !ok {
		fmt.Fprintf(w, `<div class="error-message">No more items to load.</div>`)
		return
	}
	
	// Slice files based on offset
	pageSize := 20
	start := offset
	end := offset + pageSize
	
	if start >= len(files) {
		// No more items
		return
	}
	
	if end > len(files) {
		end = len(files)
	}
	
	pagedFiles := files[start:end]
	data["Files"] = pagedFiles
	
	// Set content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	// Render just the gallery items for this batch
	for _, file := range pagedFiles {
		// Render a basic item
		fmt.Fprintf(w, `
		<div class="gallery-item">
			<a href="/detail/%s?key=%s">
				<img src="/thumbnail/%s" alt="%s" loading="lazy">
				<div class="gallery-item-details">
					<p title="%s"><strong>File:</strong> %s</p>
				</div>
			</a>
		</div>`, file.Name, data["CurrentKey"], file.Name, file.Description, file.Name, file.Name)
	}
	
	// Add new load-more trigger if there are more items
	if end < len(files) {
		newOffset := end
		fmt.Fprintf(w, `
		<div id="load-more-trigger" 
			 hx-get="/gallery/load-more" 
			 hx-include="[name='key'], [name='tag'], [name='show_type'], #sortOrder, #searchQuery"
			 hx-vals='{"offset": "%d"}'
			 hx-target="#gallery-progressive-container" 
			 hx-swap="beforeend"
			 hx-trigger="intersect once">
			<div class="load-more-indicator">Loading more items...</div>
		</div>`, newOffset)
	}
}

// renderGallery handles both the full page load and the HTMX partial updates.
// It now calls prepareGalleryData and then executes the appropriate template.
func (h *Handlers) renderGallery(w http.ResponseWriter, r *http.Request, isPartial bool) {
	log := h.Log.With("handler", "renderGallery")

	// Determine the correct template name/block based on the request context
	// --- REVISED TEMPLATE LOGIC ---
	var templateName string
	if !isPartial {
		// If the handler determined this is NOT a partial request (e.g., direct load or refresh),
		// ALWAYS render the full page, regardless of path.
		templateName = "gallery.html"
		log = log.With("render_mode", "full_page")
	} else {
		// If it IS a partial request, determine WHICH block based on path.
		if strings.HasSuffix(r.URL.Path, "/items") {
			// HTMX request for just the items (filtering, sorting)
			templateName = "gallery_items.html"
			log = log.With("render_mode", "items_only (partial)")
		} else {
			// HTMX request for the content block (polling via /gallery?partial=true)
			templateName = "gallery-content"
			log = log.With("render_mode", "content_block (partial)")
		}
	}

	// Sanity check - ensure a template name was set
	if templateName == "" {
		log.Error("Could not determine template name", "path", r.URL.Path, "isPartial", isPartial)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// --- END REVISED TEMPLATE LOGIC ---

	// --- Prepare Data ---
	data, err := h.prepareGalleryData(r)
	if err != nil {
		// Check if the error is specifically invalid access key
		if errors.Is(err, ErrInvalidAccessKey) {
			// prepareGalleryData already logged the warning
			http.NotFound(w, r) // Return 404 for invalid key
		} else {
			// Handle other errors during data preparation
			log.Error("Failed to prepare gallery data", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			// TODO: Consider rendering an error template block instead of raw HTML?
			fmt.Fprintf(w, `<div class="error-message">Error preparing gallery data. Please try again later.</div>`)
		}
		return
	}

	// Extract item count for logging *after* data preparation is successful
	itemCount := 0
	if files, ok := data["Files"].([]templates.FileInfoWrapper); ok {
		itemCount = len(files)
	}

	// --- Render Template ---
	// Set content type to ensure proper rendering
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	log.Info("Rendering gallery template", "template_target", templateName, "item_count", itemCount)
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
	// --- Check for Direct Refresh on /gallery/items URL ---
	// If the path is /gallery/items BUT it's NOT an HTMX request,
	// it means the user refreshed the page on that specific URL.
	// We should serve the full page, applying the filters from the URL.
	// if strings.HasSuffix(r.URL.Path, "/items") && r.Header.Get("HX-Request") != "true" {
	// 	log := h.Log.With("handler", "GalleryHandler")
	// 	log.Debug("Handling direct browser request (refresh) on /gallery/items path", "url", r.URL.String())
	// 	// Render the full page, using the query params from the /items URL
	// 	h.renderGallery(w, r, false)
	// 	return // Stop processing here
	// }
	// --- End Refresh Check ---

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
	// --- Check for Direct Browser Request (Refresh) ---
	// If the HX-Request header is NOT present, it's a normal browser request (e.g., refresh)
	// In this case, render the FULL page, not just the items fragment.
	if r.Header.Get("HX-Request") != "true" {
		log := h.Log.With("handler", "GalleryItemsHandler")
		log.Debug("Handling direct browser request (refresh) on /gallery/items path", "url", r.URL.String())
		// Render the full page, applying filters from the URL
		h.renderGallery(w, r, false)
		return // Stop processing here
	}
	// --- End Refresh Check ---

	// If it IS an HTMX request, proceed to render just the items block.

	// --- REFACTORED LOGIC for HTMX ---
	log := h.Log.With("handler", "GalleryItemsHandler", "request_type", "htmx")

	// 1. Prepare data
	data, err := h.prepareGalleryData(r)
	if err != nil {
		// Check if the error is specifically invalid access key
		if errors.Is(err, ErrInvalidAccessKey) {
			// prepareGalleryData already logged the warning
			// For HTMX, return 404 but maybe with a minimal response that HTMX can swap?
			// Or let HTMX handle the 404 status directly.
			// Let's just return 404, HTMX might show its default error handling.
			http.NotFound(w, r)
		} else {
			// Handle other errors during data preparation
			log.Error("Failed to prepare gallery data for HTMX items request", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			// Send a simple error message back for the swap
			fmt.Fprintf(w, `<div id="gallery-items"><div class="error-message">Error loading gallery items.</div></div>`)
		}
		return
	}

	// 2. Render Out-of-Band tag links first
	log.Debug("Rendering OOB tag links")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = h.Tmpl.ExecuteTemplate(w, "tag_links_oob.html", data)
	if err != nil {
		// Log error, but continue to attempt rendering items
		log.Error("Failed to execute tag_links_oob.html template", "error", err)
	}

	// 2b. Render Out-of-Band active tag input
	log.Debug("Rendering OOB active tag input")
	err = h.Tmpl.ExecuteTemplate(w, "active_tag_input_oob.html", data)
	if err != nil {
		// Log error, but continue to attempt rendering items
		log.Error("Failed to execute active_tag_input_oob.html template", "error", err)
	}

	// 3. Render main gallery items block
	log.Debug("Rendering gallery items block")
	err = h.Tmpl.ExecuteTemplate(w, "gallery_items.html", data)
	if err != nil {
		// Log error. If OOB also failed, headers might not be written yet.
		log.Error("Failed to execute gallery_items.html template", "error", err)
		if _, ok := w.Header()["Content-Type"]; !ok {
			// Only write header if nothing has been successfully written yet
			w.WriteHeader(http.StatusInternalServerError)
		}
		// Don't write body again if OOB might have partially succeeded
	}

	// --- END REFACTORED LOGIC for HTMX ---

	// --- REFACTOR NEEDED --- // REMOVED OLD COMMENT BLOCK
	// Ideal structure:
	// 1. Call a function like prepareGalleryData(r) -> (data, error)
	// 2. Check error
	// 3. h.Tmpl.ExecuteTemplate(w, "gallery_items.html", data)
}

// --- Placeholder Handlers Removed ---

// Helper function removed - defined elsewhere
