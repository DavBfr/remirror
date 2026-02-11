package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// get_storage_path converts a hash ID to a sharded directory path
// e.g., "abcdef123..." -> "data/ab/cd/ef/abcdef123..."
func get_storage_path(dataDir string, hashID string) string {
	if len(hashID) < 6 {
		return path.Join(dataDir, "_short", hashID)
	}
	return path.Join(dataDir, hashID[0:2], hashID[2:4], hashID[4:6], hashID)
}

// normalize_path removes the cacheRoot prefix from a file path
func normalize_path(filePath string) string {
	if cacheRoot == "" {
		return filePath
	}
	prefix := cacheRoot
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if strings.HasPrefix(filePath, prefix) {
		return strings.TrimPrefix(filePath, prefix)
	}
	return filePath
}

// hash_path generates a SHA256 hash of the normalized file path
func hash_path(filePath string) string {
	// Normalize the path first
	normalizedPath := normalize_path(filePath)
	hash := sha256.Sum256([]byte(normalizedPath))
	return hex.EncodeToString(hash[:])
}
