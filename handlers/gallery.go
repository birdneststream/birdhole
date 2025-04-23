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
	templateName := "gallery.html"
	if isPartial {
		// This expects a template block named "gallery_items.html"
		// defined within your main template file or loaded separately.
		templateName = "gallery_items.html"
	}
	log = log.With("template", templateName, "partial", isPartial)

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
	sortOrder := r.URL.Query().Get("sort") // Expected: "new" or "old"

	log.Debug("Gallery view parameters", "isAdmin", isAdmin, "activeTag", activeTag, "sortOrder", sortOrder)

	// Use FileInfoWrapper to include Snippet
	var filteredFiles []templates.FileInfoWrapper // Changed type here
	uniqueTags := make(map[string]struct{})       // Using map as a set for unique tags

	for _, fileInfo := range allFilesInfo {
		log.Debug("Processing file for gallery", "filename", fileInfo.Name, "hidden", fileInfo.Hidden, "tags", fileInfo.Tags)

		// Collect all unique tags from accessible files
		isVisible := !fileInfo.Hidden || isAdmin
		if isVisible {
			for _, tag := range fileInfo.Tags {
				if tag != "" {
					uniqueTags[strings.TrimSpace(tag)] = struct{}{} // Trim spaces from tags
				}
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
	tagList := make([]string, 0, len(uniqueTags))
	for tag := range uniqueTags {
		tagList = append(tagList, tag)
	}
	sort.Strings(tagList) // Keep tag list sorted for consistent display

	// REMOVED DEBUG LOG

	data := map[string]interface{}{
		"Files":        filteredFiles,
		"UniqueTags":   tagList,
		"ActiveTag":    activeTag,
		"SortOrder":    sortOrder,
		"CurrentKey":   queryKey, // Pass original query key for constructing links/URLs in template
		"IsAdmin":      isAdmin,
		"RefreshParam": fmt.Sprintf("?ts=%d", time.Now().UnixNano()), // Basic cache buster for polling
	}
	// --- End Template Data ---

	// --- Render Template ---
	log.Info("Rendering gallery template", "template", templateName, "item_count", len(filteredFiles))
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

// GalleryHandler serves the full gallery page HTML.
func (h *Handlers) GalleryHandler(w http.ResponseWriter, r *http.Request) {
	h.renderGallery(w, r, false) // isPartial = false
}

// GalleryItemsHandler serves the partial HTML fragment containing just the gallery items.
// This is typically triggered by HTMX for tag filtering, sorting, or auto-refresh.
func (h *Handlers) GalleryItemsHandler(w http.ResponseWriter, r *http.Request) {
	h.renderGallery(w, r, true) // isPartial = true
}

// --- Placeholder Handlers Removed ---
