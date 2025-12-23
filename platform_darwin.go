//go:build darwin

package machineid

import (
	"os/exec"
	"strings"
)

func getEnvironmentType() string {
	// Check sysctl for machdep.cpu.features containing VMM
	cmd := exec.Command("sysctl", "machdep.cpu.features")
	out, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(out), "VMM") {
			return "vm"
		}
	}
	return "physical"
}