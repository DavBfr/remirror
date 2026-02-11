package remirror

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"
)

// init_metadata_db initializes the SQLite database for storing ETags
func init_metadata_db(dataPath string) error {
	dbPath := path.Join(dataPath, "metadata.db")

	// Ensure the data directory exists
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Use URI format with proper SQLite options
	dsn := "file:" + dbPath + "?cache=shared&mode=rwc"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Use DELETE mode instead of WAL to avoid I/O issues on network/unstable filesystems
	_, err = db.Exec("PRAGMA journal_mode=DELETE")
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to set journal mode: %w", err)
	}

	// Set busy timeout to 5 seconds to handle concurrent writes
	_, err = db.Exec("PRAGMA busy_timeout=5000")
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to set busy timeout: %w", err)
	}

	// Enable synchronous mode for data safety
	_, err = db.Exec("PRAGMA synchronous=NORMAL")
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to set synchronous: %w", err)
	}

	// Set cache size for better performance
	_, err = db.Exec("PRAGMA cache_size=2000")
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to set cache size: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Create the metadata table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			id TEXT PRIMARY KEY,
			path TEXT UNIQUE NOT NULL,
			etag TEXT NOT NULL,
			last_modified DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create files table: %w", err)
	}

	metaDB = db
	return nil
}

// store_metadata saves ETag and Last-Modified for a given file path
func store_metadata(filePath, etag, lastModified string) error {
	if metaDB == nil {
		return fmt.Errorf("metadata database not initialized")
	}

	// Serialize database writes to prevent SQLITE_BUSY errors
	metaDB_mu.Lock()
	defer metaDB_mu.Unlock()

	// Normalize the path to remove cacheRoot prefix
	filePath = normalize_path(filePath)
	// Compute hash ID for this file
	hashID := hash_path(filePath)

	// Avoid updating updated_at when metadata hasn't changed.
	var existingEtag string
	var existingLastModified string
	err := metaDB.QueryRow(`SELECT etag, last_modified FROM files WHERE id = ?`, hashID).Scan(&existingEtag, &existingLastModified)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if lastModified == "" {
		lastModified = existingLastModified
	}
	if lastModified == "" {
		lastModified = time.Now().UTC().Format(http.TimeFormat)
	}
	if err == nil && existingEtag == etag && existingLastModified == lastModified {
		vlog("metadata unchanged for %s (id:%s)", filePath, hashID[:8])
		return nil
	}

	if err == nil {
		vlog("metadata updated for %s (id:%s): etag %q -> %q, last_modified %q -> %q", filePath, hashID[:8], existingEtag, etag, existingLastModified, lastModified)
	} else {
		vlog("metadata inserted for %s (id:%s): etag %q, last_modified %q", filePath, hashID[:8], etag, lastModified)
	}

	_, err = metaDB.Exec(
		`INSERT OR REPLACE INTO files (id, path, etag, last_modified, updated_at) VALUES (?, ?, ?, ?, ?)`,
		hashID, filePath, etag, lastModified, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		vlog("metadata exec failed: %v", err)
	}
	return err
}

// get_metadata retrieves stored ETag and Last-Modified for a given file path
// Returns: (etag, lastModified, storagePathOrEmpty, error)
func get_metadata(filePath string) (string, string, string, error) {
	if metaDB == nil {
		return "", "", "", fmt.Errorf("metadata database not initialized")
	}

	// Serialize database writes to prevent SQLITE_BUSY errors
	metaDB_mu.Lock()
	defer metaDB_mu.Unlock()

	// Normalize the path to remove cacheRoot prefix
	filePath = normalize_path(filePath)
	hashID := hash_path(filePath)

	var etag string
	var lastModified string
	err := metaDB.QueryRow(`SELECT etag, last_modified FROM files WHERE id = ?`, hashID).Scan(&etag, &lastModified)
	if err == sql.ErrNoRows {
		vlog("metadata not found for %s (id:%s)", filePath, hashID[:8])
		return "", "", "", nil // No metadata stored, not an error
	}
	if err == nil {
		vlog("metadata loaded for %s (id:%s): etag=%q last_modified=%q", filePath, hashID[:8], etag, lastModified)
		storagePath := get_storage_path(cacheRoot, hashID)
		return etag, lastModified, storagePath, nil
	}
	return "", "", "", err
}

func touch_metadata(filePath string) {
	if metaDB == nil {
		return
	}
	// Serialize database writes to prevent SQLITE_BUSY errors
	metaDB_mu.Lock()
	defer metaDB_mu.Unlock()

	// Normalize the path to remove cacheRoot prefix
	filePath = normalize_path(filePath)
	hashID := hash_path(filePath)
	if _, err := metaDB.Exec(
		`UPDATE files SET updated_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), hashID,
	); err != nil {
		vlog("metadata touch failed for %s (id:%s): %v", filePath, hashID[:8], err)
	}
}
