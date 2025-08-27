package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"birdhole/config"
	"birdhole/file"

	"git.mills.io/prologic/bitcask"
)

const (
	metaPrefix     = "meta:"
	filePrefix     = "file:"
	thumbPrefix    = "thumb:"
	viewHashPrefix = "viewhash:"
	derivedPrefix  = "derived:"
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

	// Ensure the storage directories exist
	if err := os.MkdirAll(dbPath, 0o750); err != nil {
		log.Error("Failed to create storage directory", "path", dbPath, "error", err)
		return nil, fmt.Errorf("failed to create storage directory %q: %w", dbPath, err)
	}

	// Create files directory
	if err := os.MkdirAll(cfg.FilesPath, 0o750); err != nil {
		log.Error("Failed to create files directory", "path", cfg.FilesPath, "error", err)
		return nil, fmt.Errorf("failed to create files directory %q: %w", cfg.FilesPath, err)
	}

	// Create thumbnails directory
	if err := os.MkdirAll(cfg.ThumbnailsPath, 0o750); err != nil {
		log.Error("Failed to create thumbnails directory", "path", cfg.ThumbnailsPath, "error", err)
		return nil, fmt.Errorf("failed to create thumbnails directory %q: %w", cfg.ThumbnailsPath, err)
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

// Helper function to create view hash keys
func viewHashKey(filename string) []byte {
	return []byte(viewHashPrefix + filename)
}

// derivedKey creates a key for derived file content
func derivedKey(parentFilename, derivedFilename string) []byte {
	return []byte(derivedPrefix + parentFilename + ":" + derivedFilename)
}

// ThumbnailFilename generates thumbnail filename by replacing extension with .jpg
func ThumbnailFilename(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		// Replace extension with .jpg
		return filename[:len(filename)-len(ext)] + ".jpg"
	}
	// No extension, just add .jpg
	return filename + ".jpg"
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
// Accepts content as bytes instead of io.Reader.
// Optionally stores compressed thumbnail data.
func (s *Storage) PutFile(ctx context.Context, filename string, info file.Info, contentBytes []byte, compressedThumbnailBytes []byte) error {
	mKey := metaKey(filename)

	// Write file content directly to filesystem
	filePath := filepath.Join(s.cfg.FilesPath, filename)
	if err := os.WriteFile(filePath, contentBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write file to disk: %w", err)
	}

	// Write thumbnail to filesystem if provided
	if compressedThumbnailBytes != nil {
		thumbnailPath := filepath.Join(s.cfg.ThumbnailsPath, ThumbnailFilename(filename))
		// Decompress thumbnail before writing to disk
		decompressed, err := DecompressContent(compressedThumbnailBytes)
		if err != nil {
			s.log.Warn("Failed to decompress thumbnail, storing compressed", "filename", filename, "error", err)
			// Store compressed if decompression fails
			if err := os.WriteFile(thumbnailPath, compressedThumbnailBytes, 0o600); err != nil {
				return fmt.Errorf("failed to write compressed thumbnail to disk: %w", err)
			}
		} else {
			if err := os.WriteFile(thumbnailPath, decompressed, 0o600); err != nil {
				return fmt.Errorf("failed to write thumbnail to disk: %w", err)
			}
		}
	}

	// Marshal the metadata (still store in Bitcask)
	metaData, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal file.Info: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store only metadata in Bitcask now
	err = s.db.Put(mKey, metaData)
	if err != nil {
		s.log.Error("Failed to put metadata in storage", "filename", filename, "key", string(mKey), "error", err)
		// Clean up filesystem files if metadata storage fails
		if removeErr := os.Remove(filePath); removeErr != nil {
			s.log.Warn("Failed to clean up file after metadata storage failure", "path", filePath, "error", removeErr)
		}
		if compressedThumbnailBytes != nil {
			thumbnailPath := filepath.Join(s.cfg.ThumbnailsPath, ThumbnailFilename(filename))
			if removeErr := os.Remove(thumbnailPath); removeErr != nil {
				s.log.Warn("Failed to clean up thumbnail after metadata storage failure", "path", thumbnailPath, "error", removeErr)
			}
		}
		return fmt.Errorf("failed to put metadata for %q: %w", filename, err)
	}

	s.log.Info("File stored successfully", "filename", filename, "original_size", len(contentBytes), "metadata_stored", true)
	return nil
}

// GetStoredObject retrieves the metadata from Bitcask and content from filesystem.
func (s *Storage) GetStoredObject(ctx context.Context, filename string) (*StoredObject, error) {
	mKey := metaKey(filename)

	var infoData []byte
	var info file.Info
	var getErr error

	// Get metadata from Bitcask
	s.mu.RLock()
	infoData, getErr = s.db.Get(mKey)
	s.mu.RUnlock()

	if getErr != nil {
		if errors.Is(getErr, bitcask.ErrKeyNotFound) {
			s.log.Warn("File metadata not found in storage", "filename", filename, "key", string(mKey))
			return nil, fmt.Errorf("%w: file %q", os.ErrNotExist, filename)
		}
		s.log.Error("Failed to get file metadata from storage", "filename", filename, "key", string(mKey), "error", getErr)
		return nil, fmt.Errorf("failed to get file %q: %w", filename, getErr)
	}

	// Unmarshal metadata
	if err := json.Unmarshal(infoData, &info); err != nil {
		s.log.Error("Failed to unmarshal stored metadata", "filename", filename, "key", string(mKey), "error", err)
		return nil, fmt.Errorf("failed to unmarshal metadata for %q: %w", filename, err)
	}

	// Read content from filesystem
	// Safe: filename is validated by regex and path is safely constructed with filepath.Join
	filePath := filepath.Join(s.cfg.FilesPath, filename)
	contentBytes, err := os.ReadFile(filePath) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			s.log.Warn("File content not found on filesystem", "filename", filename, "path", filePath)
			return nil, fmt.Errorf("%w: file %q", os.ErrNotExist, filename)
		}
		s.log.Error("Failed to read file content from filesystem", "filename", filename, "path", filePath, "error", err)
		return nil, fmt.Errorf("failed to read file %q: %w", filename, err)
	}

	storedObj := &StoredObject{
		Metadata:  info,
		ContentGz: contentBytes, // Now uncompressed content from filesystem
	}

	s.log.Debug("Retrieved stored object from filesystem", "filename", filename)
	return storedObj, nil
}

// PutThumbnail stores thumbnail data to filesystem.
func (s *Storage) PutThumbnail(ctx context.Context, filename string, compressedThumbnailBytes []byte) error {
	thumbnailPath := filepath.Join(s.cfg.ThumbnailsPath, ThumbnailFilename(filename))

	// Decompress thumbnail before writing to disk
	decompressed, err := DecompressContent(compressedThumbnailBytes)
	if err != nil {
		s.log.Warn("Failed to decompress thumbnail, storing compressed", "filename", filename, "error", err)
		// Store compressed if decompression fails
		if err := os.WriteFile(thumbnailPath, compressedThumbnailBytes, 0o600); err != nil {
			return fmt.Errorf("failed to write compressed thumbnail to disk: %w", err)
		}
	} else {
		if err := os.WriteFile(thumbnailPath, decompressed, 0o600); err != nil {
			return fmt.Errorf("failed to write thumbnail to disk: %w", err)
		}
	}

	s.log.Debug("Standalone thumbnail stored to filesystem", "filename", filename, "path", thumbnailPath)
	return nil
}

// GetThumbnail retrieves thumbnail data from filesystem.
func (s *Storage) GetThumbnail(ctx context.Context, filename string) ([]byte, error) {
	// Safe: filename is validated by regex and path is safely constructed with filepath.Join
	thumbnailPath := filepath.Join(s.cfg.ThumbnailsPath, ThumbnailFilename(filename))

	thumbnailData, err := os.ReadFile(thumbnailPath) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			s.log.Debug("Thumbnail not found on filesystem", "filename", filename, "path", thumbnailPath)
			return nil, fmt.Errorf("%w: thumbnail for %q", os.ErrNotExist, filename)
		}
		s.log.Error("Failed to read thumbnail from filesystem", "filename", filename, "path", thumbnailPath, "error", err)
		return nil, fmt.Errorf("failed to get thumbnail %q: %w", filename, err)
	}
	s.log.Debug("Retrieved thumbnail from storage", "filename", filename, "compressed_size", len(thumbnailData))
	return thumbnailData, nil
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

// CompressContent takes raw data and returns the gzipped bytes.
func CompressContent(rawData []byte) ([]byte, error) {
	if len(rawData) == 0 {
		return []byte{}, nil // Return empty if input is empty
	}
	var compressedBuf bytes.Buffer
	// Use BestCompression for potentially smaller files
	gzWriter, err := gzip.NewWriterLevel(&compressedBuf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer for CompressContent: %w", err)
	}
	if _, err = gzWriter.Write(rawData); err != nil {
		if closeErr := gzWriter.Close(); closeErr != nil {
			// Log close error but don't return it since write error is more important
			return nil, fmt.Errorf("failed to write data to gzip writer: %w (close error: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("failed to write data to gzip writer: %w", err)
	}
	if err = gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}
	return compressedBuf.Bytes(), nil
}

// IncrementViewCountUnique checks if a salted+hashed IP has viewed the file today
// and increments the main view counter only if it's a unique view.
func (s *Storage) IncrementViewCountUnique(ctx context.Context, filename string, clientIP string) error {
	mKey := metaKey(filename)
	vhKey := viewHashKey(filename)
	log := s.log.With("function", "IncrementViewCountUnique", "filename", filename)

	// --- Generate Salted Hash ---
	if s.cfg.ViewCounterSalt == "" {
		log.Error("ViewCounterSalt is not configured. Cannot track unique views.")
		// Don't increment anything if salt is missing
		return errors.New("view counter salt is not configured")
	}
	salt := s.cfg.ViewCounterSalt
	hasher := sha256.New()
	hasher.Write([]byte(salt + clientIP)) // Salt first
	hashedIPBytes := hasher.Sum(nil)
	// Use Base64 encoding for storage
	currentViewHash := base64.StdEncoding.EncodeToString(hashedIPBytes)

	// Add hash to logger context AFTER it's generated
	log = log.With("clientIPHash", currentViewHash)

	// --- Read-Modify-Write Cycle (Locked) ---
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Get existing view hashes
	var existingHashes string
	hashListData, err := s.db.Get(vhKey)
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			// Key not found means this is the first view today
			log.Debug("No existing view hash list found. First view.")
			existingHashes = "" // Start with empty list
		} else {
			// Other error reading hash list
			log.Error("Failed to get view hash list", "error", err)
			return fmt.Errorf("failed to get view hash list for %q: %w", filename, err)
		}
	} else {
		existingHashes = string(hashListData)
	}

	// 2. Check if current hash already exists
	// Simple check for existence (can be slow for very long lists, but ok for 24h expiry)
	hashLine := currentViewHash + "\n"
	if strings.Contains(existingHashes, hashLine) {
		log.Debug("View hash already exists. Not incrementing.")
		return nil // Already counted today
	}

	// 3. If unique, increment main counter in metadata
	log.Debug("Unique view detected. Incrementing counter.")

	// 3a. Get current metadata
	infoData, err := s.db.Get(mKey)
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			log.Error("Metadata not found when trying to increment unique view count (should not happen if hash list exists or is new)", "filename", filename)
			return fmt.Errorf("%w: file %q metadata missing during unique view increment", os.ErrNotExist, filename)
		}
		log.Error("Failed to get metadata for unique view increment", "error", err)
		return fmt.Errorf("failed to get metadata for %q: %w", filename, err)
	}

	// 3b. Unmarshal metadata
	var info file.Info
	if err := json.Unmarshal(infoData, &info); err != nil {
		log.Error("Failed to unmarshal metadata for unique view increment", "error", err)
		return fmt.Errorf("failed to unmarshal metadata for %q: %w", filename, err)
	}

	// 3c. Increment view count
	info.Views++
	log.Debug("Incremented main view count", "new_count", info.Views)

	// 3d. Marshal updated metadata
	updatedInfoData, err := json.Marshal(info)
	if err != nil {
		log.Error("Failed to marshal updated metadata for unique view increment", "error", err)
		return fmt.Errorf("failed to marshal updated metadata for %q: %w", filename, err)
	}

	// 4. Append new hash to list
	updatedHashes := existingHashes + hashLine

	// 5. Put updated metadata
	if err := s.db.Put(mKey, updatedInfoData); err != nil {
		log.Error("Failed to put updated metadata for unique view increment", "error", err)
		// Don't attempt to write hash list if meta fails
		return fmt.Errorf("failed to put updated metadata for %q: %w", filename, err)
	}

	// 6. Put updated hash list
	if err := s.db.Put(vhKey, []byte(updatedHashes)); err != nil {
		log.Error("Failed to put updated view hash list", "error", err)
		// This is problematic - meta counter is updated, but hash list isn't.
		// Maybe attempt rollback? For now, just return error.
		return fmt.Errorf("failed to put updated view hash list for %q: %w", filename, err)
	}

	// --- End Read-Modify-Write ---

	return nil
}

// GetAllFilesInfo retrieves metadata for all files by scanning only metadata keys.
func (s *Storage) GetAllFilesInfo(ctx context.Context) ([]file.Info, error) {
	s.log.Debug("GetAllFilesInfo: Scanning for keys with prefix", "prefix", metaPrefix)
	var filesInfo []file.Info

	// Use a shorter lock duration and release between operations
	s.mu.RLock()
	defer s.mu.RUnlock() // Ensure unlock happens

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
	// Note: Unlock is handled by defer above
	if err != nil {
		// This captures errors from the Get/Unmarshal inside the scan or context cancellation
		s.log.Error("Error during metadata scan in GetAllFilesInfo", "error", err)
		return nil, err
	}

	s.log.Info("Retrieved metadata for all files via scan", "count", len(filesInfo))
	return filesInfo, nil
}

// DeleteFile removes the file metadata, content, and thumbnail (if exists) from storage.
func (s *Storage) DeleteFile(ctx context.Context, filename string) error {
	mKey := metaKey(filename)
	vKey := viewHashKey(filename)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if metadata exists first
	exists := s.db.Has(mKey)
	if !exists {
		s.log.Warn("Attempted to delete non-existent file (checked meta key)", "filename", filename, "key", string(mKey))
		return fmt.Errorf("%w: file metadata %q not found", os.ErrNotExist, filename)
	}

	// Get file metadata to check for derived files
	infoData, err := s.db.Get(mKey)
	if err == nil {
		var info file.Info
		if json.Unmarshal(infoData, &info) == nil && len(info.DerivedFiles) > 0 {
			// Delete all derived files
			for _, derivedFile := range info.DerivedFiles {
				dKey := derivedKey(filename, derivedFile.Filename)
				if delErr := s.db.Delete(dKey); delErr != nil && !errors.Is(delErr, bitcask.ErrKeyNotFound) {
					s.log.Warn("Failed to delete derived file during cleanup",
						"parent", filename,
						"derived", derivedFile.Filename,
						"error", delErr)
				}
			}
		}
	}

	// Delete metadata from Bitcask
	err = s.db.Delete(mKey)
	if err != nil {
		s.log.Error("Failed to delete metadata", "filename", filename, "key", string(mKey), "error", err)
	}

	// Delete file from filesystem
	filePath := filepath.Join(s.cfg.FilesPath, filename)
	errFile := os.Remove(filePath)
	if errFile != nil && !os.IsNotExist(errFile) {
		s.log.Error("Failed to delete file from filesystem", "filename", filename, "path", filePath, "error", errFile)
		if err == nil {
			err = errFile
		}
	}

	// Delete thumbnail from filesystem
	thumbnailPath := filepath.Join(s.cfg.ThumbnailsPath, ThumbnailFilename(filename))
	errThumb := os.Remove(thumbnailPath)
	if errThumb != nil && !os.IsNotExist(errThumb) {
		s.log.Error("Failed to delete thumbnail from filesystem", "filename", filename, "path", thumbnailPath, "error", errThumb)
		if err == nil {
			err = errThumb
		}
	}

	// Delete view hash data (ignore ErrKeyNotFound)
	errView := s.db.Delete(vKey)
	if errView != nil && !errors.Is(errView, bitcask.ErrKeyNotFound) {
		s.log.Error("Failed to delete view hash data", "filename", filename, "key", string(vKey), "error", errView)
		if err == nil {
			err = errView
		}
	}

	if err != nil {
		return fmt.Errorf("failed during deletion process for %q: %w", filename, err)
	}

	s.log.Info("File and associated data deleted successfully", "filename", filename)
	return nil
}

// CleanupExpired iterates through metadata keys and deletes expired files (all keys).
func (s *Storage) CleanupExpired(ctx context.Context) (int, error) {
	s.log.Info("Starting expired file cleanup (scanning meta keys)")
	var deletedCount int
	// Store tuples: [metaKey, fileKey, viewHashKey, filename]
	var keysToDelete [][][]byte
	var filenamesToDelete []string

	// Use read lock only for scan
	s.mu.RLock()
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
			keysToDelete = append(keysToDelete, [][]byte{key, fileKey(filename), viewHashKey(filename)})
			filenamesToDelete = append(filenamesToDelete, filename)
		}
		return nil // Continue scan
	})
	s.mu.RUnlock() // Unlock after scan completes

	if scanErr != nil {
		s.log.Error("Error during metadata scan in CleanupExpired", "error", scanErr)
		return 0, fmt.Errorf("cleanup failed during key scan: %w", scanErr)
	}

	if len(keysToDelete) == 0 {
		s.log.Info("CleanupExpired: No expired files found to delete")
		return 0, nil
	}

	s.log.Info("CleanupExpired: Found expired keys to delete", "count", len(keysToDelete))

	// Process deletions
	for i := 0; i < len(keysToDelete); i++ {
		metaKeyToDelete := keysToDelete[i][0]
		fileKeyToDelete := keysToDelete[i][1]
		viewHashKeyToDelete := keysToDelete[i][2]
		filename := strings.TrimPrefix(string(metaKeyToDelete), metaPrefix)

		// Perform deletion - short WLock for each tuple
		s.mu.Lock()
		delMetaErr := s.db.Delete(metaKeyToDelete)
		delFileErr := s.db.Delete(fileKeyToDelete)
		delViewHashErr := s.db.Delete(viewHashKeyToDelete)
		s.mu.Unlock()

		if delMetaErr != nil {
			s.log.Error("CleanupExpired: Failed to delete expired meta key", "key", string(metaKeyToDelete), "error", delMetaErr)
			// Continue processing other keys
		}
		if delFileErr != nil {
			s.log.Error("CleanupExpired: Failed to delete expired file key", "key", string(fileKeyToDelete), "error", delFileErr)
			// Continue processing other keys
		}
		if delViewHashErr != nil {
			s.log.Error("CleanupExpired: Failed to delete expired view hash key", "key", string(viewHashKeyToDelete), "error", delViewHashErr)
			// Continue processing other keys
		}

		// Count as deleted only if meta key deletion succeeded (primary key)
		if delMetaErr == nil {
			deletedCount++
			s.log.Info("CleanupExpired: Deleted expired file", "filename", filename)
		}
	}

	// After deleting keys, merge the database to reclaim space if any files were deleted.
	if deletedCount > 0 {
		s.log.Info("CleanupExpired: Merging database to reclaim space", "deleted_count", deletedCount)
		s.mu.Lock()
		err := s.db.Merge()
		s.mu.Unlock()
		if err != nil {
			s.log.Error("CleanupExpired: Failed to merge database", "error", err)
			// We return the count of deleted files, but also the error from merge
			return deletedCount, fmt.Errorf("failed to merge database after cleanup: %w", err)
		}
		s.log.Info("CleanupExpired: Database merge completed successfully")
	}

	s.log.Info("Finished expired file cleanup run", "deleted_count", deletedCount)
	return deletedCount, nil // Return total count, errors are logged
}

// PutDerivedFile stores derived file content (IRC/ANSI extracted from PNG)
func (s *Storage) PutDerivedFile(ctx context.Context, parentFilename, derivedFilename string, content []byte) error {
	dKey := derivedKey(parentFilename, derivedFilename)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store derived content in Bitcask (content is small enough)
	if err := s.db.Put(dKey, content); err != nil {
		s.log.Error("Failed to store derived file",
			"parent", parentFilename,
			"derived", derivedFilename,
			"error", err)
		return fmt.Errorf("failed to store derived file %q: %w", derivedFilename, err)
	}

	s.log.Debug("Stored derived file",
		"parent", parentFilename,
		"derived", derivedFilename,
		"size", len(content))

	return nil
}

// GetDerivedFile retrieves derived file content
func (s *Storage) GetDerivedFile(ctx context.Context, parentFilename, derivedFilename string) ([]byte, error) {
	dKey := derivedKey(parentFilename, derivedFilename)

	s.mu.RLock()
	defer s.mu.RUnlock()

	content, err := s.db.Get(dKey)
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			return nil, fmt.Errorf("%w: derived file %q", os.ErrNotExist, derivedFilename)
		}
		return nil, fmt.Errorf("failed to get derived file %q: %w", derivedFilename, err)
	}

	return content, nil
}

// DeleteDerivedFile removes a derived file
func (s *Storage) DeleteDerivedFile(ctx context.Context, parentFilename, derivedFilename string) error {
	dKey := derivedKey(parentFilename, derivedFilename)

	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Delete(dKey)
	if err != nil && !errors.Is(err, bitcask.ErrKeyNotFound) {
		return fmt.Errorf("failed to delete derived file %q: %w", derivedFilename, err)
	}

	return nil
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
