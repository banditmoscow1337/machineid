//go:build windows

package machineid

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func getEnvironmentType() string {
	// 1. Check for specific VM Registry Keys
	// These keys are commonly present in guest environments.

	// Microsoft Hyper-V
	if checkKeyExists(`SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`) {
		return "vm"
	}
	// VMware
	if checkKeyExists(`SOFTWARE\VMware, Inc.\VMware Tools`) {
		return "vm"
	}
	// Oracle VirtualBox
	if checkKeyExists(`SOFTWARE\Oracle\VirtualBox Guest Additions`) {
		return "vm"
	}

	// 2. Check BIOS Information via Registry
	// This reads the same DMI data that 'wmic computersystem' would access,
	// but via the registry at HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()

		// Helper to safely get a string value
		getString := func(name string) string {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				return ""
			}
			return val
		}

		model := getString("SystemProductName")
		manufacturer := getString("SystemManufacturer")

		m := strings.ToLower(model)
		man := strings.ToLower(manufacturer)

		// Check for generic VM terms in model/manufacturer
		if strings.Contains(m, "virtual") || strings.Contains(m, "vmware") || strings.Contains(m, "kvm") {
			return "vm"
		}

		// Windows Containers / Hyper-V specific checks
		if strings.Contains(man, "microsoft corporation") && strings.Contains(m, "virtual") {
			return "vm"
		}
	}

	return "physical"
}

// checkKeyExists returns true if the specified registry key exists under HKLM.
func checkKeyExists(subKey string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}