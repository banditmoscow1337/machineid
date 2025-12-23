//go:build !linux && !windows && !darwin

package machineid

func getEnvironmentType() string {
	return "unknown"
}