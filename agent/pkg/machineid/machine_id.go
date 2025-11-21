package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GetMachineID returns deterministic agent ID based on BIOS serial hash.
func GetMachineID() (string, error) {
	serial, err := getBIOSSerialNumber()
	if err != nil {
		return "", fmt.Errorf("failed to get BIOS serial number: %w", err)
	}
	if serial == "" {
		return "", fmt.Errorf("BIOS serial number is empty")
	}

	hash := sha256.Sum256([]byte(serial))
	hashStr := hex.EncodeToString(hash[:])

	return "agent-" + hashStr[:16], nil
}

func getBIOSSerialNumber() (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "(Get-WmiObject Win32_BIOS).SerialNumber")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("PowerShell command failed: %w", err)
	}
	serial := strings.TrimSpace(string(output))
	if serial == "" {
		return "", fmt.Errorf("BIOS serial number is empty")
	}
	return serial, nil
}

// GetMachineIDWithFallback attempts to retrieve the machine ID, falling back to hostname.
func GetMachineIDWithFallback() string {
	if id, err := GetMachineID(); err == nil {
		return id
	}
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "agent-unknown"
	}
	return "agent-" + host
}
