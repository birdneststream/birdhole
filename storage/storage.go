package storage

import (
	"birdhole/config"
	"birdhole/file"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors" // Added missing import
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"git.mills.io/prologic/bitcask"
)

// StoredObject holds the metadata and the compressed content.
type StoredObject struct {
	Metadata  file.Info `json:"metadata"`
	ContentGz []byte    `json:"content_gz"` // Gzipped content
}

// Storage manages the interaction with the Bitcask key-value store.
type Storage struct {
	db     *bitcask.Bitcask
	dbPath string
	cfg    *config.Config
	log    *slog.Logger
	mu     sync.RWMutex
}

// NewStorage initializes the storage system.
func NewStorage(cfg *config.Config, logger *slog.Logger) (*Storage, error) {
	dbPath := cfg.BitcaskPath // Corrected field name
	log := logger.With("component", "storage")

	// Ensure the storage directory exists
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		log.Error("Failed to create storage directory", "path", dbPath, "error", err)
		return nil, fmt.Errorf("failed to create storage directory %q: %w", dbPath, err)
	}

	// Set max value size to 100 MB
	maxValSize := uint64(100 * 1024 * 1024) // Explicitly cast to uint64
	db, err := bitcask.Open(dbPath,
		bitcask.WithSync(true),               // Ensure writes are synced
		bitcask.WithMaxValueSize(maxValSize), // Add MaxValueSize option
	)
	if err != nil {
		log.Error("Failed to open bitcask database", "path", dbPath, "error", err)
		return nil, fmt.Errorf("failed to open bitcask at %q: %w", dbPath, err)
	}
	log.Info("Bitcask database opened", "path", dbPath)

	s := &Storage{
		db:     db,
		dbPath: dbPath,
		cfg:    cfg,
		log:    log,
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Storage) Close() error {
	s.log.Info("Closing bitcask database")
	return s.db.Close()
}

// GenerateUniqueFilename creates a short, random, unique base32 filename of the specified length.
func (s *Storage) GenerateUniqueFilename(ctx context.Context, extension string, length int) (string, error) {
	// Validate length
	const minLen = 6
	const maxLen = 16
	if length < minLen || length > maxLen {
		length = 8 // Default to 8 if invalid length provided
		s.log.Warn("Invalid urllen requested, defaulting to 8", "requested_length", length)
	}

	maxAttempts := 10 // Prevent infinite loops

	b := make([]byte, length) // Use requested length
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)

	for i := 0; i < maxAttempts; i++ {
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("failed to read random bytes: %w", err)
		}
		// Use lowercase and remove padding for shorter, cleaner URLs
		// Trim to the desired length after encoding
		filename := strings.ToLower(enc.EncodeToString(b))[:length]
		if extension != "" {
			// Ensure the extension starts with a dot if it's not empty
			if !strings.HasPrefix(extension, ".") {
				extension = "." + extension
			}
			filename = filename + extension // Keep original extension
		}

		// Check if the key already exists
		key := []byte(filename)
		s.mu.RLock()
		has := s.db.Has(key) // Corrected assignment
		s.mu.RUnlock()
		// Note: Original bitcask Has doesn't return an error. If a version does, error handling would be needed here.
		if !has {
			s.log.Debug("Generated unique filename", "filename", filename, "length", length)
			return filename, nil
		}
		s.log.Debug("Filename collision, retrying", "filename", filename, "attempt", i+1)
	}

	return "", fmt.Errorf("failed to generate unique filename of length %d after %d attempts", length, maxAttempts)
}

// PutFile stores the file content and metadata, compressing the content.
func (s *Storage) PutFile(ctx context.Context, filename string, info file.Info, content io.Reader) error {
	key := []byte(filename)

	// Read content
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Compress content
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzWriter.Write(contentBytes); err != nil {
		gzWriter.Close() // Ensure writer is closed even on error
		return fmt.Errorf("failed to compress content: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}
	compressedBytes := compressedBuf.Bytes()

	storedObj := StoredObject{
		Metadata:  info,
		ContentGz: compressedBytes,
	}

	// Marshal the StoredObject
	data, err := json.Marshal(storedObj)
	if err != nil {
		return fmt.Errorf("failed to marshal StoredObject: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store in Bitcask
	err = s.db.Put(key, data)
	if err != nil {
		s.log.Error("Failed to put file in storage", "filename", filename, "error", err)
		return fmt.Errorf("failed to put file %q: %w", filename, err)
	}
	s.log.Info("File stored successfully", "filename", filename, "original_size", len(contentBytes), "compressed_size", len(compressedBytes))
	return nil
}

// GetStoredObject retrieves the StoredObject (metadata + compressed content).
func (s *Storage) GetStoredObject(ctx context.Context, filename string) (*StoredObject, error) {
	key := []byte(filename)

	s.mu.RLock()
	data, err := s.db.Get(key)
	s.mu.RUnlock()

	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			s.log.Warn("File not found in storage", "filename", filename)
			// Use a standard error type for not found
			return nil, fmt.Errorf("%w: file %q", os.ErrNotExist, filename)
		}
		s.log.Error("Failed to get file from storage", "filename", filename, "error", err)
		return nil, fmt.Errorf("failed to get file %q: %w", filename, err)
	}

	var storedObj StoredObject
	if err := json.Unmarshal(data, &storedObj); err != nil {
		s.log.Error("Failed to unmarshal stored object", "filename", filename, "error", err)
		return nil, fmt.Errorf("failed to unmarshal data for %q: %w", filename, err)
	}

	s.log.Debug("Retrieved stored object", "filename", filename)
	return &storedObj, nil
}

// DecompressContent takes gzipped data and returns the decompressed bytes.
func DecompressContent(compressedData []byte) ([]byte, error) {
	if len(compressedData) == 0 {
		return []byte{}, nil // Return empty if input is empty
	}
	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	decompressedData, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}
	return decompressedData, nil
}

// GetAllFilesInfo retrieves metadata for all files.
func (s *Storage) GetAllFilesInfo(ctx context.Context) ([]file.Info, error) {
	s.log.Debug("GetAllFilesInfo: Using Keys() method...")
	// Sync before getting keys, just in case
	if errSync := s.db.Sync(); errSync != nil {
		s.log.Error("GetAllFilesInfo: Failed to sync database before Keys()", "error", errSync)
		return nil, fmt.Errorf("failed to sync database before Keys(): %w", errSync)
	}

	var filesInfo []file.Info
	processedKeys := 0
	getKeysError := error(nil) // Variable to store errors from Get/Unmarshal inside the loop

	s.mu.RLock() // Lock for the duration of key iteration and Gets
	keysChan := s.db.Keys()
	// Need to iterate the channel fully while holding the lock
	for key := range keysChan {
		// Check context cancellation within the loop
		select {
		case <-ctx.Done():
			s.log.Warn("GetAllFilesInfo: Context cancelled during key iteration")
			getKeysError = ctx.Err()
			break // Exit the loop
		default:
		}
		if getKeysError != nil {
			break
		}

		processedKeys++
		keyStr := string(key)
		s.log.Debug("GetAllFilesInfo: Processing key from Keys() channel", "key", keyStr)

		data, errGet := s.db.Get(key)
		if errGet != nil {
			s.log.Error("GetAllFilesInfo: Failed to get data for key from Keys()", "key", keyStr, "error", errGet)
			if errors.Is(errGet, bitcask.ErrKeyNotFound) {
				s.log.Debug("GetAllFilesInfo: Key not found during Get (using Keys), skipping", "key", keyStr)
				continue // Key might have been deleted, continue
			}
			// Store the first critical error and stop processing
			getKeysError = fmt.Errorf("failed getting key %s from Keys(): %w", keyStr, errGet)
			break
		}
		s.log.Debug("GetAllFilesInfo: Successfully got data for key (using Keys)", "key", keyStr, "data_len", len(data))

		var storedObj StoredObject
		if errUnmarshal := json.Unmarshal(data, &storedObj); errUnmarshal != nil {
			s.log.Error("GetAllFilesInfo: Failed to unmarshal data for key (using Keys)", "key", keyStr, "error", errUnmarshal)
			// Maybe skip corrupted data? Let's skip for now.
			continue
		}
		s.log.Debug("GetAllFilesInfo: Successfully unmarshalled data for key (using Keys)", "key", keyStr, "filename", storedObj.Metadata.Name)

		filesInfo = append(filesInfo, storedObj.Metadata)
	}
	s.mu.RUnlock() // Unlock after iterating through keys

	s.log.Debug("GetAllFilesInfo: Finished processing keys from channel", "processed_keys", processedKeys)

	// Check for errors encountered during Get/Unmarshal
	if getKeysError != nil {
		s.log.Error("Error during key processing in GetAllFilesInfo", "error", getKeysError)
		return nil, getKeysError // Return the actual error encountered
	}

	s.log.Info("Retrieved metadata for all files", "count", len(filesInfo))
	return filesInfo, nil
}

// DeleteFile removes a file from storage.
func (s *Storage) DeleteFile(ctx context.Context, filename string) error {
	key := []byte(filename)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if key exists before deleting
	has := s.db.Has(key) // Corrected assignment
	if !has {
		s.log.Warn("Attempted to delete non-existent file", "filename", filename)
		return fmt.Errorf("%w: file %q for deletion", os.ErrNotExist, filename) // Use standard not found error
	}

	err := s.db.Delete(key)
	if err != nil {
		s.log.Error("Failed to delete file from storage", "filename", filename, "error", err)
		return fmt.Errorf("failed to delete file %q: %w", filename, err)
	}
	s.log.Info("File deleted successfully", "filename", filename)
	return nil
}

// CleanupExpired iterates through all items and deletes expired ones.
func (s *Storage) CleanupExpired(ctx context.Context) (int, error) {
	s.log.Info("Starting expired file cleanup")
	var deletedCount int
	var keysToDelete [][]byte

	s.mu.RLock() // Initial read lock for scanning keys
	scanErr := s.db.Scan(nil, func(key []byte) error {
		// No need to get data here, just collect keys
		keysToDelete = append(keysToDelete, key)
		return nil
	})
	s.mu.RUnlock() // Release read lock

	if scanErr != nil {
		s.log.Error("Cleanup: Error during key scan", "error", scanErr)
		return 0, fmt.Errorf("cleanup failed during key scan: %w", scanErr)
	}

	if len(keysToDelete) == 0 {
		s.log.Info("Cleanup: No files found to check for expiry")
		return 0, nil
	}

	s.log.Debug("Cleanup: Found potential candidates for expiry", "count", len(keysToDelete))

	deletedKeysInBatch := 0
	// Process deletions potentially in batches or one by one with individual locking
	for _, key := range keysToDelete {
		filename := string(key)
		shouldDelete := false

		// Get data for expiry check - short RLock
		s.mu.RLock()
		data, err := s.db.Get(key)
		s.mu.RUnlock()

		if err != nil {
			if errors.Is(err, bitcask.ErrKeyNotFound) {
				s.log.Debug("Cleanup: Key disappeared before expiry check", "key", filename)
				continue // Already deleted or expired in another run
			}
			s.log.Error("Cleanup: Failed to get data for expiry check", "key", filename, "error", err)
			continue // Skip this key, try others
		}

		var storedObj StoredObject
		if err := json.Unmarshal(data, &storedObj); err != nil {
			s.log.Error("Cleanup: Failed to unmarshal data for expiry check", "key", filename, "error", err)
			continue // Skip this key
		}

		if storedObj.Metadata.KeyExpiry != 0 && time.Now().Unix() > storedObj.Metadata.KeyExpiry {
			shouldDelete = true
			s.log.Debug("Cleanup: Identified expired file", "filename", storedObj.Metadata.Name, "expiry", storedObj.Metadata.KeyExpiry)
		}

		if shouldDelete {
			// Perform deletion - short WLock
			s.mu.Lock()
			delErr := s.db.Delete(key)
			s.mu.Unlock()

			if delErr != nil {
				s.log.Error("Cleanup: Failed to delete expired file", "key", filename, "error", delErr)
				// Continue processing other keys
			} else {
				deletedCount++
				deletedKeysInBatch++
				s.log.Info("Cleanup: Deleted expired file", "filename", filename)
			}
		}
	}

	s.log.Info("Finished expired file cleanup run", "deleted_count", deletedCount)
	return deletedCount, nil // Return total count, error handling is logged
}

// CheckExpiry runs the cleanup task periodically.
func (s *Storage) CheckExpiry(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		s.log.Info("Automatic expiry check disabled (interval <= 0)")
		return
	}
	s.log.Info("Starting periodic expiry check", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately
	if _, err := s.CleanupExpired(ctx); err != nil {
		s.log.Error("Initial expiry cleanup failed", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			s.log.Debug("Expiry check ticker triggered")
			if _, err := s.CleanupExpired(ctx); err != nil {
				s.log.Error("Periodic expiry cleanup failed", "error", err)
			}
		case <-ctx.Done():
			s.log.Info("Stopping periodic expiry check due to context cancellation")
			return
		}
	}
}
