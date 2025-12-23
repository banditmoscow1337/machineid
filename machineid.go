package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	// cachedRawID stores the raw machine identifier (e.g., UUID or MAC hash) once resolved.
	cachedRawID string
	// cachedPrefix stores the environment type (e.g., "vm", "docker", "physical").
	cachedPrefix string

	// mu guards the initialization of the cache.
	// We deliberately use a Mutex + bool flag instead of sync.Once.
	// Rationale: sync.Once prevents retries. If getMachineID() fails due to a transient error
	// (e.g., temporary permission issue), we want subsequent calls to retry rather than
	// permanently caching the failure or returning a nil result forever.
	mu          sync.Mutex
	initialized bool

	netInterfaces    = net.Interfaces
	getEnvTypeFunc   = getEnvironmentType
	getMachineIDFunc = getMachineID
)

// loadInfo attempts to resolve and cache the machine ID and environment type.
// It is idempotent on success but allows retries on failure.
func loadInfo() error {
	mu.Lock()
	defer mu.Unlock()

	// Fast path: if already successfully initialized, return immediately.
	if initialized {
		return nil
	}

	// 1. Determine Environment Type
	// We detect if we are running in a VM, Container, or Physical hardware.
	// This helps scope the ID (e.g., a container might want to know it's a container).
	prefix := getEnvTypeFunc()

	// 2. Resolve Unique ID
	// Attempt to fetch the OS-specific unique ID (e.g., /etc/machine-id on Linux, Registry/BIOS on Windows).
	id, err := getMachineIDFunc()

	// 3. Fallback: Network Hardware ID
	// If the OS-specific ID is missing (os.ErrNotExist) or returned an empty string,
	// we fall back to hashing the MAC addresses of the network interfaces.
	// This ensures we always return *some* ID, even on stripped-down systems.
	if errors.Is(err, os.ErrNotExist) || (err == nil && id == "") {
		id, err = getHardwareId()
	} else if err != nil {
		// If a specific error occurred (e.g., Permission Denied), we fail hard so the user knows
		// something is wrong with their environment configuration.
		return err
	}

	// Double-check: If we still failed to get an ID after fallback, return the error.
	// We do NOT set initialized=true, ensuring the next call attempts the resolution again.
	if err != nil {
		return err
	}

	// Success: Update cache and freeze state.
	cachedRawID = id
	cachedPrefix = prefix
	initialized = true
	return nil
}

// ID returns the unique machine ID, prefixed with the environment type.
// The ID is a SHA256 hash of the raw machine identifier to anonymize the source data.
//
// Format: "<environment>:<hash>"
// Example: "physical:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
func ID() (string, error) {
	if err := loadInfo(); err != nil {
		return "", err
	}

	// Note: We access cachedRawID without a lock here because 'initialized' is true,
	// meaning the cache is immutable for the lifetime of the process.
	hash, err := protect(cachedRawID)
	if err != nil {
		return "", err
	}

	return cachedPrefix + ":" + hash, nil
}

// ProtectedID returns a unique ID hashed with an app-specific key.
// Use this to generate separate IDs for different applications on the same machine,
// preventing cross-app tracking.
func ProtectedID(appID string) (string, error) {
	if err := loadInfo(); err != nil {
		return "", err
	}

	// Salt the ID with the appID before hashing.
	hash, err := protect(cachedRawID + ":" + appID)
	if err != nil {
		return "", err
	}

	return cachedPrefix + ":" + hash, nil
}

// protect hashes the input string using SHA256 to ensure a fixed-length, anonymized output.
func protect(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty machine id")
	}
	hash := sha256.New()
	if _, err := hash.Write([]byte(s)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getHardwareId generates a pseudo-ID based on the MAC addresses of physical network interfaces.
// This is used as a last-resort fallback when OS-specific IDs (BIOS/Registry/etc) are unavailable.
func getHardwareId() (string, error) {
	interfaces, err := netInterfaces()
	if err != nil {
		return "", err
	}

	var macs []string
	for _, iface := range interfaces {
		// Filter out Loopback (127.0.0.1) and interfaces without MAC addresses.
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		// Heuristic Filter: Ignore interfaces created by virtualization tools (Docker, KVM, VPNs).
		// We only want "real" hardware interfaces to ensure the ID remains stable
		// if the user spins up a new Docker container or VPN.
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "docker") ||
			strings.Contains(name, "veth") ||
			strings.Contains(name, "tun") ||
			strings.Contains(name, "tap") {
			continue
		}

		macs = append(macs, iface.HardwareAddr.String())
	}

	// Sort to ensure the order of interfaces doesn't affect the generated ID.
	sort.Strings(macs)

	if len(macs) == 0 {
		return "", errors.New("no valid network interfaces found for hardware ID fallback")
	}
	return strings.Join(macs, ","), nil
}