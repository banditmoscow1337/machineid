package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// =========================================================================================
// Test Helpers & Mocks
// =========================================================================================

// resetCache clears the global state so we can test loadInfo() multiple times.
func resetCache() {
	mu.Lock()
	defer mu.Unlock()
	initialized = false
	cachedRawID = ""
	cachedPrefix = ""
}

// mockInterfaces creates a function compatible with net.Interfaces logic.
func mockInterfaces(ifaces []net.Interface, err error) func() ([]net.Interface, error) {
	return func() ([]net.Interface, error) {
		return ifaces, err
	}
}

// =========================================================================================
// Unit Tests
// =========================================================================================

func TestProtect(t *testing.T) {
	// Case 1: Valid Input
	// We expect a valid SHA256 hex string.
	input := "test-id"
	hash, err := protect(input)
	if err != nil {
		t.Fatalf("protect(%q) returned error: %v", input, err)
	}
	
	// Verify manual hash calculation
	expectedHash := sha256.Sum256([]byte(input))
	expectedHex := hex.EncodeToString(expectedHash[:])
	
	if hash != expectedHex {
		t.Errorf("protect() hash mismatch.\nGot:  %s\nWant: %s", hash, expectedHex)
	}

	// Case 2: Empty Input
	// Should return an error as per logic.
	_, err = protect("   ") // TrimSpace is used internally
	if err == nil {
		t.Error("protect() expected error for empty input, got nil")
	}
	if err.Error() != "empty machine id" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestID_And_ProtectedID_Flow(t *testing.T) {
	resetCache()
	defer resetCache()

	// Mock valid environment and machine ID
	getEnvTypeFunc = func() string { return "test-env" }
	getMachineIDFunc = func() (string, error) { return "test-machine-id", nil }
	
	// Restore mocks after test
	defer func() {
		getEnvTypeFunc = getEnvironmentType
		getMachineIDFunc = getMachineID
	}()

	// 1. Test ID()
	id, err := ID()
	if err != nil {
		t.Fatalf("ID() failed: %v", err)
	}

	// ID format is prefix:hash
	if !strings.HasPrefix(id, "test-env:") {
		t.Errorf("ID() missing prefix. Got: %s", id)
	}

	// 2. Test ProtectedID()
	// Should reuse the cached info loaded by ID()
	appID := "my-app"
	pID, err := ProtectedID(appID)
	if err != nil {
		t.Fatalf("ProtectedID() failed: %v", err)
	}

	// Verify it's different from the raw ID
	if pID == id {
		t.Error("ProtectedID() should be different from standard ID()")
	}
	
	// Verify format
	if !strings.HasPrefix(pID, "test-env:") {
		t.Errorf("ProtectedID() missing prefix. Got: %s", pID)
	}
}

func TestLoadInfo_Idempotency(t *testing.T) {
	resetCache()
	defer resetCache()

	callCount := 0
	
	// Mock that increments a counter to verify it's only called once
	getMachineIDFunc = func() (string, error) {
		callCount++
		return "unique-id", nil
	}
	defer func() { getMachineIDFunc = getMachineID }()

	// First call
	if err := loadInfo(); err != nil {
		t.Fatalf("First loadInfo failed: %v", err)
	}
	
	// Second call (should hit fast path "if initialized return nil")
	if err := loadInfo(); err != nil {
		t.Fatalf("Second loadInfo failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("loadInfo() did not cache results. getMachineID called %d times, expected 1", callCount)
	}
}

func TestLoadInfo_Concurrency(t *testing.T) {
	resetCache()
	defer resetCache()

	// Mock a slow operation to force race conditions if locking is broken
	getMachineIDFunc = func() (string, error) {
		return "concurrent-id", nil
	}
	defer func() { getMachineIDFunc = getMachineID }()

	var wg sync.WaitGroup
	routines := 20
	
	for i := 0; i < routines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ID(); err != nil {
				t.Errorf("Concurrent ID() call failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

// =========================================================================================
// Hardware ID Fallback Tests (getHardwareId)
// =========================================================================================

func TestGetHardwareID_Logic(t *testing.T) {
	// Restore real implementation after tests
	defer func() { netInterfaces = net.Interfaces }()

	tests := []struct {
		name          string
		mockIfaces    []net.Interface
		mockErr       error
		expectError   bool
		expectedMatch string // Partial match expectation
	}{
		{
			name:        "Network Error",
			mockIfaces:  nil,
			mockErr:     errors.New("network failure"),
			expectError: true,
		},
		{
			name:        "No Valid Interfaces (Empty)",
			mockIfaces:  []net.Interface{},
			mockErr:     nil,
			expectError: true, // "no valid network interfaces found"
		},
		{
			name: "Filtered Interfaces (Docker/Loopback)",
			mockIfaces: []net.Interface{
				{Name: "lo", Flags: net.FlagLoopback, HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0}}, // Should skip (Loopback)
				{Name: "docker0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0x02, 0x42, 0, 0, 0, 0}}, // Should skip (Name filter)
				{Name: "veth1234", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0x02, 0x42, 0, 0, 0, 1}}, // Should skip (Name filter)
			},
			mockErr:     nil,
			expectError: true, // All filtered out -> "no valid interfaces"
		},
		{
			name: "Valid Interface (Eth0)",
			mockIfaces: []net.Interface{
				{Name: "eth0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
			},
			mockErr:       nil,
			expectError:   false,
			expectedMatch: "aa:bb:cc:dd:ee:ff",
		},
		{
			name: "Sorting Logic (Eth1 vs Eth0)",
			mockIfaces: []net.Interface{
				{Name: "eth1", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0x22, 0x22, 0x22, 0x22, 0x22, 0x22}},
				{Name: "eth0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}},
			},
			mockErr:       nil,
			expectError:   false,
			// The logic sorts MACs, so 11... comes before 22...
			// joined by comma: "11:...,22:..."
			expectedMatch: "11:11:11:11:11:11,22:22:22:22:22:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netInterfaces = mockInterfaces(tt.mockIfaces, tt.mockErr)
			
			id, err := getHardwareId()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil. ID: %s", id)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !strings.Contains(id, tt.expectedMatch) {
					t.Errorf("ID mismatch.\nGot: %s\nExpected to contain: %s", id, tt.expectedMatch)
				}
			}
		})
	}
}

// =========================================================================================
// LoadInfo Fallback Logic Tests
// =========================================================================================

func TestLoadInfo_Fallbacks(t *testing.T) {
	resetCache()
	defer resetCache()

	// Save original hooks
	origGetMachineID := getMachineIDFunc
	origNetInterfaces := netInterfaces
	defer func() {
		getMachineIDFunc = origGetMachineID
		netInterfaces = origNetInterfaces
	}()

	// 1. Primary ID Failure -> Fallback to Hardware ID
	t.Run("Fallback_Success", func(t *testing.T) {
		resetCache()
		
		// Mock MachineID returning NotExist (e.g., missing /etc/machine-id)
		getMachineIDFunc = func() (string, error) {
			return "", os.ErrNotExist
		}

		// Mock Hardware ID success
		netInterfaces = mockInterfaces([]net.Interface{
			{Name: "eth0", HardwareAddr: net.HardwareAddr{0xAA, 0, 0, 0, 0, 0xBB}},
		}, nil)

		err := loadInfo()
		if err != nil {
			t.Fatalf("loadInfo failed during fallback: %v", err)
		}
		// Verify we got the hardware ID (we can check cachedRawID via unsafe or just trust no error)
		if cachedRawID == "" {
			t.Error("Cached ID is empty after fallback")
		}
	})

	// 2. Primary ID Empty -> Fallback
	t.Run("Fallback_On_Empty_String", func(t *testing.T) {
		resetCache()
		
		getMachineIDFunc = func() (string, error) {
			return "", nil // No error, but empty string
		}
		
		// Use Mock that returns a known MAC
		netInterfaces = mockInterfaces([]net.Interface{
			{Name: "wlan0", HardwareAddr: net.HardwareAddr{0xCC, 0, 0, 0, 0, 0xDD}},
		}, nil)

		err := loadInfo()
		if err != nil {
			t.Fatalf("loadInfo failed on empty ID fallback: %v", err)
		}
		if cachedRawID == "" {
			t.Error("Cached ID empty")
		}
	})

	// 3. Primary ID Hard Error -> Fail (No Fallback)
	t.Run("Hard_Error_Fails", func(t *testing.T) {
		resetCache()
		
		expectedErr := errors.New("permission denied")
		getMachineIDFunc = func() (string, error) {
			return "", expectedErr
		}

		err := loadInfo()
		if err != expectedErr {
			t.Errorf("Expected hard error %v, got %v", expectedErr, err)
		}
		if initialized {
			t.Error("Should not set initialized=true on failure")
		}
	})

	// 4. Fallback Failure -> Fail
	t.Run("Fallback_Error_Fails", func(t *testing.T) {
		resetCache()

		getMachineIDFunc = func() (string, error) {
			return "", os.ErrNotExist
		}
		// Mock netInterfaces failing
		netInterfaces = func() ([]net.Interface, error) {
			return nil, errors.New("network down")
		}

		err := loadInfo()
		if err == nil {
			t.Error("Expected error when both primary and fallback fail, got nil")
		}
	})
}

// =========================================================================================
// Platform Specific Logic Mocks (Linux/Docker Example)
// =========================================================================================

// Note: To test platform_linux.go specifically, you would need to export `osReadFile`
// and `osStat` hooks in that file similarly to `machineid.go`.
// The following test demonstrates how to test the Docker detection logic 
// assuming those hooks are present.

func TestEnvironmentType_Linux_Detection(t *testing.T) {
	// This test simulates platform_linux.go logic.
	// Since build tags restrict compilation, this logic is usually tested 
	// by actually running on Linux or using a build-tag-agnostic refactor.
	// For this example, we mock the outcome by replacing `getEnvironmentType` 
	// in the main logic flow, effectively testing the *integration* of different env types.
	
	resetCache()
	defer resetCache()
	defer func() { getEnvTypeFunc = getEnvironmentType }() // Restore

	scenarios := []struct {
		mockReturn string
		expected   string
	}{
		{"docker", "docker"},
		{"vm", "vm"},
		{"physical", "physical"},
	}

	for _, s := range scenarios {
		t.Run(s.mockReturn, func(t *testing.T) {
			resetCache()
			// Mock the low-level detection function
			getEnvTypeFunc = func() string { return s.mockReturn }
			// Mock ID so we don't fail there
			getMachineIDFunc = func() (string, error) { return "id", nil }

			id, _ := ID()
			// Expected format: type:hash
			expectedPrefix := s.expected + ":"
			if !strings.HasPrefix(id, expectedPrefix) {
				t.Errorf("Expected prefix %s, got ID %s", expectedPrefix, id)
			}
		})
	}
}