package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// DefaultInstancePrefix is the prefix used for default instance names.
	DefaultInstancePrefix = "CPA-"
	instanceIDFilename    = "instance_id"
)

var (
	idMu     sync.Mutex
	cachedID string
)

func isValidHex4(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// GetOrGenerateInstanceID retrieves the persistent instance ID from stateDir,
// or generates a new 4-character hex ID (e.g. "8F3B") and persists it atomically.
// Thread-safe and protected against race conditions and file permission issues.
func GetOrGenerateInstanceID(stateDir string) string {
	idMu.Lock()
	defer idMu.Unlock()

	// If already resolved and cached in-process, return immediately
	if cachedID != "" && isValidHex4(cachedID) {
		return cachedID
	}

	if stateDir != "" {
		idPath := filepath.Join(stateDir, instanceIDFilename)
		if data, err := os.ReadFile(idPath); err == nil {
			id := strings.TrimSpace(string(data))
			if isValidHex4(id) {
				cachedID = strings.ToUpper(id)
				return cachedID
			}
		}
	}

	// Generate random 2 bytes -> 4 hex chars with cryptographically secure PRNG
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		// Defensive fallback if entropy source is temporarily unavailable
		return fmt.Sprintf("%04X", os.Getpid()&0xFFFF)
	}
	id := strings.ToUpper(hex.EncodeToString(buf))

	// Persist atomically if stateDir is specified
	if stateDir != "" {
		if errDir := os.MkdirAll(stateDir, 0700); errDir == nil {
			idPath := filepath.Join(stateDir, instanceIDFilename)
			if tmpFile, errTmp := os.CreateTemp(stateDir, "instance_id_*.tmp"); errTmp == nil {
				tmpPath := tmpFile.Name()
				_ = tmpFile.Chmod(0600)
				_, _ = tmpFile.Write([]byte(id))
				_ = tmpFile.Sync()
				_ = tmpFile.Close()
				if errRename := os.Rename(tmpPath, idPath); errRename != nil {
					_ = os.Remove(tmpPath)
				}
			}
		}
	}

	cachedID = id
	return id
}

// ResetCachedInstanceID resets in-memory cached ID for test isolation.
func ResetCachedInstanceID() {
	idMu.Lock()
	defer idMu.Unlock()
	cachedID = ""
}

// FormatInstanceName returns the custom name if non-empty,
// otherwise generates a privacy-preserving instance name: CPA-<ShortID>.
func FormatInstanceName(customName, instanceID string) string {
	if trimmed := strings.TrimSpace(customName); trimmed != "" {
		return trimmed
	}
	if !isValidHex4(instanceID) {
		instanceID = "0001"
	}
	return DefaultInstancePrefix + strings.ToUpper(instanceID)
}
