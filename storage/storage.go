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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"git.mills.io/prologic/bitcask"
)

const (
	metaPrefix = "meta:"
	filePrefix = "file:"
)

// StoredObject holds the metadata and the compressed content.
// This struct is now primarily used as a return type for GetStoredObject,
// it's not stored directly as a single JSON value anymore.
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

// Helper function to create prefixed keys
func metaKey(filename string) []byte {
	return []byte(metaPrefix + filename)
}

func fileKey(filename string) []byte {
	return []byte(filePrefix + filename)
}

// GenerateUniqueFilename creates a short, random, unique base32 filename of the specified length.
func (s *Storage) GenerateUniqueFilename(ctx context.Context, extension string, length int) (string, error) {
	const minLen = 6
	const maxLen = 16
	if length < minLen || length > maxLen {
		length = 8 // Default to 8 if invalid length provided
		s.log.Warn("Invalid urllen requested, defaulting to 8", "requested_length", length)
	}

	maxAttempts := 10 // Prevent infinite loops

	b := make([]byte, length)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)

	for i := 0; i < maxAttempts; i++ {
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("failed to read random bytes: %w", err)
		}
		baseFilename := strings.ToLower(enc.EncodeToString(b))[:length]
		filename := baseFilename
		if extension != "" {
			if !strings.HasPrefix(extension, ".") {
				extension = "." + extension
			}
			filename = filename + extension
		}

		// Check if the *metadata* key already exists
		mKey := metaKey(filename)
		s.mu.RLock()
		has := s.db.Has(mKey)
		s.mu.RUnlock()

		if !has {
			s.log.Debug("Generated unique filename", "filename", filename, "length", length)
			return filename, nil
		}
		s.log.Debug("Filename collision (checked meta key), retrying", "filename", filename, "attempt", i+1)
	}

	return "", fmt.Errorf("failed to generate unique filename of length %d after %d attempts", length, maxAttempts)
}

// PutFile stores the file metadata and content under separate keys, compressing the content.
func (s *Storage) PutFile(ctx context.Context, filename string, info file.Info, content io.Reader) error {
	mKey := metaKey(filename)
	fKey := fileKey(filename)

	// Read content
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Compress content
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzWriter.Write(contentBytes); err != nil {
		gzWriter.Close()
		return fmt.Errorf("failed to compress content: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}
	compressedBytes := compressedBuf.Bytes()

	// Marshal the metadata
	metaData, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal file.Info: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store metadata
	err = s.db.Put(mKey, metaData)
	if err != nil {
		s.log.Error("Failed to put metadata in storage", "filename", filename, "key", string(mKey), "error", err)
		return fmt.Errorf("failed to put metadata for %q: %w", filename, err)
	}

	// Store content
	err = s.db.Put(fKey, compressedBytes)
	if err != nil {
		s.log.Error("Failed to put content in storage", "filename", filename, "key", string(fKey), "error", err)
		// Attempt to delete the metadata we just wrote if content write fails
		delErr := s.db.Delete(mKey)
		if delErr != nil {
			s.log.Error("Failed to rollback metadata write after content write failure", "filename", filename, "key", string(mKey), "delete_error", delErr)
		}
		return fmt.Errorf("failed to put content for %q: %w", filename, err)
	}

	s.log.Info("File stored successfully", "filename", filename, "original_size", len(contentBytes), "compressed_size", len(compressedBytes))
	return nil
}

// GetStoredObject retrieves the metadata and compressed content from separate keys.
func (s *Storage) GetStoredObject(ctx context.Context, filename string) (*StoredObject, error) {
	mKey := metaKey(filename)
	fKey := fileKey(filename)

	var infoData, contentGz []byte
	var info file.Info
	var getErr error

	s.mu.RLock()
	infoData, getErr = s.db.Get(mKey)
	if getErr == nil {
		// Only get content if metadata was found
		contentGz, getErr = s.db.Get(fKey)
	}
	s.mu.RUnlock()

	if getErr != nil {
		if errors.Is(getErr, bitcask.ErrKeyNotFound) {
			s.log.Warn("File meta or content not found in storage", "filename", filename, "key", string(mKey)+" or "+string(fKey))
			return nil, fmt.Errorf("%w: file %q", os.ErrNotExist, filename)
		}
		s.log.Error("Failed to get file meta or content from storage", "filename", filename, "key", string(mKey)+" or "+string(fKey), "error", getErr)
		return nil, fmt.Errorf("failed to get file %q: %w", filename, getErr)
	}

	// Unmarshal metadata
	if err := json.Unmarshal(infoData, &info); err != nil {
		s.log.Error("Failed to unmarshal stored metadata", "filename", filename, "key", string(mKey), "error", err)
		return nil, fmt.Errorf("failed to unmarshal metadata for %q: %w", filename, err)
	}

	storedObj := &StoredObject{
		Metadata:  info,
		ContentGz: contentGz,
	}

	s.log.Debug("Retrieved stored object", "filename", filename)
	return storedObj, nil
}

// DecompressContent takes gzipped data and returns the decompressed bytes.
func DecompressContent(compressedData []byte) ([]byte, error) {
	if len(compressedData) == 0 {
		return []byte{}, nil // Return empty if input is empty
	}
	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		// Consider logging this error as well
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	decompressedData, err := io.ReadAll(gzReader)
	if err != nil {
		// Consider logging this error as well
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}
	return decompressedData, nil
}

// GetAllFilesInfo retrieves metadata for all files by scanning only metadata keys.
func (s *Storage) GetAllFilesInfo(ctx context.Context) ([]file.Info, error) {
	s.log.Debug("GetAllFilesInfo: Scanning for keys with prefix", "prefix", metaPrefix)
	var filesInfo []file.Info

	s.mu.RLock() // Lock for the duration of the scan
	err := s.db.Scan([]byte(metaPrefix), func(key []byte) error {
		// Check context cancellation within the loop
		select {
		case <-ctx.Done():
			s.log.Warn("GetAllFilesInfo: Context cancelled during key scan")
			return ctx.Err() // Stop the scan
		default:
		}

		// Get the metadata value associated with this key
		data, errGet := s.db.Get(key)
		if errGet != nil {
			// Log error but continue scan if possible
			s.log.Error("GetAllFilesInfo: Failed to get data for meta key during scan", "key", string(key), "error", errGet)
			if errors.Is(errGet, bitcask.ErrKeyNotFound) {
				s.log.Debug("GetAllFilesInfo: Meta key not found during Get (likely deleted during scan), skipping", "key", string(key))
				return nil // Continue scan
			}
			return fmt.Errorf("failed getting data for key %s: %w", string(key), errGet) // Stop scan on critical error
		}

		var info file.Info
		if errUnmarshal := json.Unmarshal(data, &info); errUnmarshal != nil {
			// Log error but continue scan if possible
			s.log.Error("GetAllFilesInfo: Failed to unmarshal metadata during scan", "key", string(key), "error", errUnmarshal)
			return nil // Skip corrupted data, continue scan
		}
		filesInfo = append(filesInfo, info)
		return nil // Continue scan
	})
	s.mu.RUnlock() // Unlock after scan finishes or errors

	if err != nil {
		// This captures errors from the Get/Unmarshal inside the scan or context cancellation
		s.log.Error("Error during metadata scan in GetAllFilesInfo", "error", err)
		return nil, err
	}

	s.log.Info("Retrieved metadata for all files via scan", "count", len(filesInfo))
	return filesInfo, nil
}

// DeleteFile removes both the metadata and content keys for a file.
func (s *Storage) DeleteFile(ctx context.Context, filename string) error {
	mKey := metaKey(filename)
	fKey := fileKey(filename)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if metadata key exists before deleting
	has := s.db.Has(mKey)
	if !has {
		s.log.Warn("Attempted to delete non-existent file (checked meta key)", "filename", filename)
		return fmt.Errorf("%w: file %q for deletion", os.ErrNotExist, filename)
	}

	// Delete metadata key
	errMeta := s.db.Delete(mKey)
	if errMeta != nil {
		s.log.Error("Failed to delete metadata from storage", "filename", filename, "key", string(mKey), "error", errMeta)
		// Proceed to delete file key anyway, but return the meta error
	}

	// Delete file content key
	errFile := s.db.Delete(fKey)
	if errFile != nil {
		// Log this error, especially if meta deletion succeeded
		s.log.Error("Failed to delete file content from storage", "filename", filename, "key", string(fKey), "error", errFile)
		// If meta deletion failed, return that error. If it succeeded, return this one.
		if errMeta == nil {
			return fmt.Errorf("failed to delete file content for %q: %w", filename, errFile)
		}
	}

	if errMeta != nil {
		return fmt.Errorf("failed to delete metadata for %q: %w", filename, errMeta)
	}

	s.log.Info("File deleted successfully (both meta and content)", "filename", filename)
	return nil
}

// CleanupExpired iterates through metadata keys and deletes expired files (both keys).
func (s *Storage) CleanupExpired(ctx context.Context) (int, error) {
	s.log.Info("Starting expired file cleanup (scanning meta keys)")
	var deletedCount int
	var keysToDelete [][]byte // Store keys to delete [metaKey1, fileKey1, metaKey2, fileKey2, ...]

	s.mu.RLock() // Lock for the duration of the scan
	scanErr := s.db.Scan([]byte(metaPrefix), func(key []byte) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			s.log.Warn("CleanupExpired: Context cancelled during key scan")
			return ctx.Err()
		default:
		}

		// Get metadata value
		data, errGet := s.db.Get(key)
		if errGet != nil {
			s.log.Error("CleanupExpired: Failed to get data for meta key during scan", "key", string(key), "error", errGet)
			return nil // Continue scan, skip this key
		}

		var info file.Info
		if errUnmarshal := json.Unmarshal(data, &info); errUnmarshal != nil {
			s.log.Error("CleanupExpired: Failed to unmarshal metadata during scan", "key", string(key), "error", errUnmarshal)
			return nil // Continue scan, skip corrupted key
		}

		// Check expiry
		if info.KeyExpiry != 0 && time.Now().Unix() > info.KeyExpiry {
			filename := strings.TrimPrefix(string(key), metaPrefix)
			s.log.Debug("CleanupExpired: Identified expired file", "filename", filename, "expiry", info.KeyExpiry)
			keysToDelete = append(keysToDelete, key)               // Add meta key
			keysToDelete = append(keysToDelete, fileKey(filename)) // Add corresponding file key
		}
		return nil // Continue scan
	})
	s.mu.RUnlock() // Unlock after scan

	if scanErr != nil {
		s.log.Error("Error during metadata scan in CleanupExpired", "error", scanErr)
		return 0, fmt.Errorf("cleanup failed during key scan: %w", scanErr)
	}

	if len(keysToDelete) == 0 {
		s.log.Info("CleanupExpired: No expired files found to delete")
		return 0, nil
	}

	s.log.Info("CleanupExpired: Found expired keys to delete", "count", len(keysToDelete)/2) // Each file adds 2 keys

	// Process deletions
	for i := 0; i < len(keysToDelete); i += 2 {
		metaKeyToDelete := keysToDelete[i]
		fileKeyToDelete := keysToDelete[i+1]
		filename := strings.TrimPrefix(string(metaKeyToDelete), metaPrefix)

		// Perform deletion - short WLock for each pair
		s.mu.Lock()
		delMetaErr := s.db.Delete(metaKeyToDelete)
		delFileErr := s.db.Delete(fileKeyToDelete)
		s.mu.Unlock()

		if delMetaErr != nil {
			s.log.Error("CleanupExpired: Failed to delete expired meta key", "key", string(metaKeyToDelete), "error", delMetaErr)
			// Continue processing other keys
		}
		if delFileErr != nil {
			s.log.Error("CleanupExpired: Failed to delete expired file key", "key", string(fileKeyToDelete), "error", delFileErr)
			// Continue processing other keys
		}

		// Count as deleted only if meta key deletion succeeded (primary key)
		if delMetaErr == nil {
			deletedCount++
			s.log.Info("CleanupExpired: Deleted expired file", "filename", filename)
		}
	}

	s.log.Info("Finished expired file cleanup run", "deleted_count", deletedCount)
	return deletedCount, nil // Return total count, errors are logged
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
			if _, err := s.CleanupExpired(ctx); err != nil {
				s.log.Error("Periodic expiry cleanup failed", "error", err)
			}
		case <-ctx.Done():
			s.log.Info("Stopping periodic expiry check due to context cancellation")
			return
		}
	}
}
