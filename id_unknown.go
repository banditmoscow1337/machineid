//go:build !linux && !darwin && !windows

package machineid

import "errors"

func getMachineID() (string, error) {
	return "", errors.New("os not supported")
}