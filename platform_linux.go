//go:build linux

package machineid

import (
	"os"
	"strings"
)

var osReadFile = os.ReadFile
var osStat = os.Stat

func getEnvironmentType() string {
	// 1. Check for Containerization
	
	// Check for the presence of /.dockerenv.
	// This file is created by the Docker daemon inside the container root.
	if _, err := osStat("/.dockerenv"); err == nil {
		return "docker"
	}
	
	// Check Control Groups (cgroups).
	// Processes in containers are assigned to specific cgroups. 
	// The path often contains "docker" or "kubepods" (Kubernetes).
	if cgroup, err := osReadFile("/proc/1/cgroup"); err == nil {
		cgroupData := string(cgroup)
		if strings.Contains(cgroupData, "docker") || strings.Contains(cgroupData, "kubepods") {
			return "container"
		}
	}

	// 2. Check for Virtual Machines (Hypervisors)
	// We read the DMI (Desktop Management Interface) data exposed by the kernel in sysfs.
	// Note: Reading /sys/class/dmi usually requires root or specific permissions. 
	// If we can't read it (err != nil), we fail gracefully and assume "physical".
	
	// Check Product Name
	if product, err := osReadFile("/sys/class/dmi/id/product_name"); err == nil {
		s := strings.ToLower(string(product))
		if strings.Contains(s, "virtual") || strings.Contains(s, "vmware") || strings.Contains(s, "qemu") || strings.Contains(s, "kvm") {
			return "vm"
		}
	}
	
	// Check System Vendor
	if vendor, err := osReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		s := strings.ToLower(string(vendor))
		// QEMU/KVM often puts identifiers in the vendor field.
		if strings.Contains(s, "qemu") || strings.Contains(s, "kvm") {
			return "vm"
		}
	}

	// Default assumption: Physical hardware
	return "physical"
}