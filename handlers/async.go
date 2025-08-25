package handlers

import (
	"birdhole/file"
	"birdhole/storage"
	"birdhole/templates"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/disintegration/imaging"
	_ "golang.org/x/image/webp"
)

// randomString generates a random string of specified length
func randomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based string if random fails
		return fmt.Sprintf("%d", time.Now().UnixNano())[:length]
	}
	return strings.ToLower(base32.StdEncoding.EncodeToString(bytes))[:length]
}

// UploadJob represents an async upload task
type UploadJob struct {
	ID          string
	Status      string // "processing", "completed", "failed"
	Progress    int    // 0-100
	URL         string // Result URL when completed
	Error       string // Error message if failed
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// UploadJobManager manages async upload jobs
type UploadJobManager struct {
	jobs map[string]*UploadJob
	mu   sync.RWMutex
}

// Global upload job manager
var uploadManager = &UploadJobManager{
	jobs: make(map[string]*UploadJob),
}

// GetJob retrieves a job by ID
func (m *UploadJobManager) GetJob(id string) (*UploadJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, exists := m.jobs[id]
	return job, exists
}

// CreateJob creates a new upload job
func (m *UploadJobManager) CreateJob(id string) *UploadJob {
	m.mu.Lock()
	defer m.mu.Unlock()

	job := &UploadJob{
		ID:        id,
		Status:    "processing",
		Progress:  0,
		CreatedAt: time.Now(),
	}
	m.jobs[id] = job

	// Clean up old jobs (older than 1 hour)
	go m.cleanupOldJobs()

	return job
}

// UpdateJob updates a job's status
func (m *UploadJobManager) UpdateJob(id string, status string, progress int, url string, errorMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, exists := m.jobs[id]; exists {
		job.Status = status
		job.Progress = progress
		if url != "" {
			job.URL = url
		}
		if errorMsg != "" {
			job.Error = errorMsg
		}
		if status == "completed" || status == "failed" {
			now := time.Now()
			job.CompletedAt = &now
		}
	}
}

// cleanupOldJobs removes jobs older than 1 hour
func (m *UploadJobManager) cleanupOldJobs() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, job := range m.jobs {
		if job.CreatedAt.Before(cutoff) {
			delete(m.jobs, id)
		}
	}
}

// AsyncUploadHandler initiates an async upload
func (h *Handlers) AsyncUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, h.Log, "Method not allowed", nil, http.StatusMethodNotAllowed)
		return
	}

	logger := h.Log.With("handler", "AsyncUploadHandler")

	// Generate job ID
	jobID := fmt.Sprintf("job_%d_%s", time.Now().UnixNano(), randomString(6))
	job := uploadManager.CreateJob(jobID)

	// Return job ID immediately
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"job_id": jobID,
		"status": "processing",
	}); err != nil {
		logger.Error("Failed to encode job response", "error", err)
	}

	// Process upload in background
	go h.processUploadAsync(r, job, logger)
}

// processUploadAsync processes the upload in the background
func (h *Handlers) processUploadAsync(r *http.Request, job *UploadJob, logger *slog.Logger) {
	// Parse multipart form
	maxUploadBytes := int64(h.Config.MaxUploadSizeMB) * 1024 * 1024
	r.Body = http.MaxBytesReader(nil, r.Body, maxUploadBytes)

	memoryLimit := int64(10 * 1024 * 1024) // 10 MB in memory
	err := r.ParseMultipartForm(memoryLimit)
	if err != nil {
		uploadManager.UpdateJob(job.ID, "failed", 0, "", fmt.Sprintf("Failed to parse form: %v", err))
		return
	}

	uploadManager.UpdateJob(job.ID, "processing", 20, "", "")

	fileReader, fileHeader, err := r.FormFile("file")
	if err != nil {
		uploadManager.UpdateJob(job.ID, "failed", 20, "", fmt.Sprintf("Failed to get file: %v", err))
		return
	}
	defer fileReader.Close()

	// Read file content
	contentBytes, err := io.ReadAll(fileReader)
	if err != nil {
		uploadManager.UpdateJob(job.ID, "failed", 30, "", fmt.Sprintf("Failed to read file: %v", err))
		return
	}

	uploadManager.UpdateJob(job.ID, "processing", 40, "", "")

	// Process metadata (similar to original UploadHandler)
	originalFilename := fileHeader.Filename
	ext := filepath.Ext(originalFilename)

	// Generate unique filename
	ctx := context.Background()
	uniqueFilename, genErr := h.Storage.GenerateUniqueFilename(ctx, ext, 8)
	if genErr != nil {
		uploadManager.UpdateJob(job.ID, "failed", 40, "", fmt.Sprintf("Failed to generate filename: %v", genErr))
		return
	}

	// Get form values
	description := r.FormValue("description")
	message := r.FormValue("message")
	hidden := r.FormValue("hidden") == "true"
	panorama := r.FormValue("panorama") == "true"

	// Process tags
	var tags []string
	if tagString := r.FormValue("tags"); tagString != "" {
		for _, tag := range strings.Split(tagString, ",") {
			if trimmed := strings.TrimSpace(tag); trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	uploadManager.UpdateJob(job.ID, "processing", 50, "", "")

	// Detect MIME type
	mimeType := http.DetectContentType(contentBytes)

	// Process thumbnails async if it's an image
	var compressedThumbBytes []byte
	var width, height int

	if strings.HasPrefix(mimeType, "image/") {
		uploadManager.UpdateJob(job.ID, "processing", 60, "", "Generating thumbnail...")

		// Get dimensions
		imgConfig, _, err := image.DecodeConfig(bytes.NewReader(contentBytes))
		if err == nil {
			width = imgConfig.Width
			height = imgConfig.Height

			// Generate thumbnail in background
			img, _, decodeErr := image.Decode(bytes.NewReader(contentBytes))
			if decodeErr == nil {
				thumb := imaging.Thumbnail(img, 400, 300, imaging.Lanczos)
				var thumbBuf bytes.Buffer
				if imaging.Encode(&thumbBuf, thumb, imaging.JPEG, imaging.JPEGQuality(85)) == nil {
					compressedThumbBytes, _ = storage.CompressContent(thumbBuf.Bytes())
				}
			}
		}
	}

	uploadManager.UpdateJob(job.ID, "processing", 80, "", "Storing file...")

	// Create file info
	fileInfo := file.Info{
		Name:        uniqueFilename,
		Description: description,
		Message:     message,
		Hidden:      hidden,
		Tags:        tags,
		MimeType:    mimeType,
		Size:        fileHeader.Size,
		Timestamp:   time.Now().Unix(),
		Panorama:    panorama,
		Width:       width,
		Height:      height,
	}

	// Store the file
	storeCtx := context.Background()
	err = h.Storage.PutFile(storeCtx, uniqueFilename, fileInfo, contentBytes, compressedThumbBytes)
	if err != nil {
		uploadManager.UpdateJob(job.ID, "failed", 90, "", fmt.Sprintf("Failed to store file: %v", err))
		return
	}

	// Build result URL
	baseURL := h.Config.BaseURL
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	fullURL := baseURL + uniqueFilename

	uploadManager.UpdateJob(job.ID, "completed", 100, fullURL, "")
}

// UploadStatusHandler checks the status of an async upload
func (h *Handlers) UploadStatusHandler(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job_id")
	if jobID == "" {
		jsonError(w, h.Log, "Missing job_id parameter", nil, http.StatusBadRequest)
		return
	}

	job, exists := uploadManager.GetJob(jobID)
	if !exists {
		jsonError(w, h.Log, "Job not found", nil, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(job); err != nil {
		h.Log.Error("Failed to encode job status", "error", err)
	}
}

// StreamGalleryItemsHandler streams gallery items as they're loaded
func (h *Handlers) StreamGalleryItemsHandler(w http.ResponseWriter, r *http.Request) {
	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create a channel to send items
	itemsChan := make(chan string, 100)
	done := make(chan bool)

	// Start fetching items in background
	go h.fetchGalleryItemsAsync(r, itemsChan, done)

	// Stream items as they come
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case item := <-itemsChan:
			fmt.Fprintf(w, "data: %s\n\n", item)
			flusher.Flush()
		case <-done:
			fmt.Fprintf(w, "data: {\"done\": true}\n\n")
			flusher.Flush()
			return
		case <-r.Context().Done():
			return
		}
	}
}

// fetchGalleryItemsAsync fetches gallery items in batches
func (h *Handlers) fetchGalleryItemsAsync(r *http.Request, itemsChan chan<- string, done chan<- bool) {
	defer close(done)

	// Get gallery data
	data, err := h.prepareGalleryData(r)
	if err != nil {
		return
	}

	files, ok := data["Files"].([]templates.FileInfoWrapper)
	if !ok {
		return
	}

	// Send items in batches
	batchSize := 20
	for i := 0; i < len(files); i += batchSize {
		end := i + batchSize
		if end > len(files) {
			end = len(files)
		}

		batch := files[i:end]
		batchJSON, err := json.Marshal(batch)
		if err != nil {
			continue
		}

		itemsChan <- string(batchJSON)

		// Small delay to prevent overwhelming the client
		time.Sleep(10 * time.Millisecond)
	}
}
