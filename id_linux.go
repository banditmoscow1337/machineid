//go:build linux

package machineid

import (
	"errors"
	"os"
	"strings"
)

func getMachineID() (string, error) {
	// We rely on the systemd machine-id file.
	// This ID is generated at installation (or first boot) and is generally considered
	// the standard unique ID for Linux systems.
	id, err := readFile("/etc/machine-id")
	if err != nil {
		// IMPORTANT: We return the raw error here.
		// If the file is missing (os.ErrNotExist), the caller (loadInfo) handles the fallback logic.
		// If it exists but is unreadable (os.ErrPermission), we want the user to know.
		return "", err
	}

	if id == "" {
		return "", errors.New("empty machine-id file")
	}

	return id, nil
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}