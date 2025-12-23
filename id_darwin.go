//go:build darwin

package machineid

import (
	"bytes"
	"os/exec"
	"strings"
)

func getMachineID() (string, error) {
	// Execute: ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Parse output to find IOPlatformUUID
	output := out.String()
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				// Remove quotes and whitespace
				id := strings.Trim(parts[1], " \"")
				return id, nil
			}
		}
	}

	return "", nil
}