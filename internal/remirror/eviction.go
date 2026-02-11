package remirror

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// start_eviction_scheduler starts a daily cache eviction task
func start_eviction_scheduler(dataPath string, olderThanStr string) {
	if strings.TrimSpace(olderThanStr) == "" {
		vlog("cache eviction is disabled")
		return
	}

	// Parse the duration
	olderThan, err := time.ParseDuration(olderThanStr)
	if err != nil {
		log.Printf("Warning: invalid evict_older_than value %q: %v", olderThanStr, err)
		return
	}

	if olderThan <= 0 {
		log.Printf("Warning: evict_older_than must be positive, got %v", olderThan)
		return
	}

	log.Printf("cache eviction enabled: deleting files older than %v", olderThan)

	// Run eviction immediately
	if err := evict_old_files(dataPath, olderThan); err != nil {
		log.Printf("initial cache eviction failed: %v", err)
	}

	// Schedule daily eviction in a background goroutine
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := evict_old_files(dataPath, olderThan); err != nil {
				log.Printf("scheduled cache eviction failed: %v", err)
			}
		}
	}()
}

// evict_old_files deletes cached files with updated_at older than the specified duration
func evict_old_files(dataPath string, olderThanDuration time.Duration) error {
	if metaDB == nil || olderThanDuration <= 0 {
		return nil
	}

	cutoffTime := time.Now().Add(-olderThanDuration)
	cutoffTimeStr := cutoffTime.UTC().Format(time.RFC3339)
	var deletedCount int
	var deletedSize int64

	vlog("starting cache eviction for files with updated_at before %s", cutoffTimeStr)

	// Query database for all files with updated_at < cutoffTime
	rows, err := metaDB.Query(`SELECT id, path FROM files WHERE updated_at < ?`, cutoffTimeStr)
	if err != nil {
		return fmt.Errorf("failed to query eviction candidates: %w", err)
	}
	defer rows.Close()

	type evictCandidate struct {
		id   string
		path string
	}
	var filesToEvict []evictCandidate
	for rows.Next() {
		var hashID, relPath string
		if err := rows.Scan(&hashID, &relPath); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		filesToEvict = append(filesToEvict, evictCandidate{id: hashID, path: relPath})
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating eviction candidates: %w", err)
	}

	// Delete files and their database entries
	for _, candidate := range filesToEvict {
		storagePath := get_storage_path(dataPath, candidate.id)

		// Get file size before deletion
		fileSize := int64(0)
		if info, statErr := os.Stat(storagePath); statErr == nil {
			fileSize = info.Size()
		}

		// Delete file from filesystem
		if err := os.Remove(storagePath); err != nil {
			vlog("failed to delete file %s (id:%s): %v", candidate.path, candidate.id[:8], err)
			// Continue with other files even if one fails
			continue
		}

		// Delete entry from database (serialize to prevent SQLITE_BUSY)
		metaDB_mu.Lock()
		_, delErr := metaDB.Exec(`DELETE FROM files WHERE id = ?`, candidate.id)
		metaDB_mu.Unlock()
		if delErr != nil {
			vlog("failed to delete database entry for %s (id:%s): %v", candidate.path, candidate.id[:8], delErr)
		}

		deletedCount++
		deletedSize += fileSize
		vlog("evicted file: %s (id:%s, updated_at before %s)", candidate.path, candidate.id[:8], cutoffTimeStr)
	}

	log.Printf("cache eviction complete: deleted %d files (%.2f MB)", deletedCount, float64(deletedSize)/1024/1024)
	return nil
}
