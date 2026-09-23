package ca

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed assets/russian_trusted_root_ca.pem
var RussianTrustedRootCA []byte

//go:embed assets/russian_trusted_sub_ca.pem
var RussianTrustedSubCA []byte

// GetMergedBundle returns combined Root and Intermediate CA certs
func GetMergedBundle() []byte {
	var bundle []byte
	bundle = append(bundle, RussianTrustedRootCA...)
	if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, RussianTrustedSubCA...)
	return bundle
}

// ExportToFile writes Russian CA root or merged bundle to path
func ExportToFile(path string, includeSub bool) error {
	var data []byte
	if includeSub {
		data = GetMergedBundle()
	} else {
		data = RussianTrustedRootCA
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write bundle to %s: %w", path, err)
	}
	return nil
}

// InstallToSystemStore installs Минцифры root CA into OS trust store
func InstallToSystemStore(dryRun bool) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		tmpPath := filepath.Join(os.TempDir(), "russiantrustedca.pem")
		if err := os.WriteFile(tmpPath, RussianTrustedRootCA, 0644); err != nil {
			return "", err
		}
		cmdStr := fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", tmpPath)
		if dryRun {
			return fmt.Sprintf("[DRY-RUN] %s", cmdStr), nil
		}
		cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("failed to execute security add-trusted-cert: %w, out: %s", err, string(out))
		}
		return string(out), nil

	case "linux":
		// Check for Debian/Ubuntu or RHEL/CentOS
		if _, err := os.Stat("/usr/local/share/ca-certificates"); err == nil {
			// Debian / Ubuntu
			target := "/usr/local/share/ca-certificates/russiantrustedca.crt"
			cmdStr := fmt.Sprintf("cp bundle to %s && sudo update-ca-certificates", target)
			if dryRun {
				return fmt.Sprintf("[DRY-RUN] %s", cmdStr), nil
			}
			if err := os.WriteFile(target, RussianTrustedRootCA, 0644); err != nil {
				return "", fmt.Errorf("cannot write to %s: %w", target, err)
			}
			cmd := exec.Command("sudo", "update-ca-certificates")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return string(out), fmt.Errorf("update-ca-certificates failed: %w", err)
			}
			return string(out), nil
		} else if _, err := os.Stat("/etc/pki/ca-trust/source/anchors"); err == nil {
			// RHEL / CentOS / Alma / Rocky
			target := "/etc/pki/ca-trust/source/anchors/russiantrustedca.crt"
			cmdStr := fmt.Sprintf("cp bundle to %s && sudo update-ca-trust extract", target)
			if dryRun {
				return fmt.Sprintf("[DRY-RUN] %s", cmdStr), nil
			}
			if err := os.WriteFile(target, RussianTrustedRootCA, 0644); err != nil {
				return "", fmt.Errorf("cannot write to %s: %w", target, err)
			}
			cmd := exec.Command("sudo", "update-ca-trust", "extract")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return string(out), fmt.Errorf("update-ca-trust failed: %w", err)
			}
			return string(out), nil
		}
		return "", fmt.Errorf("unsupported Linux distro certificate store layout")

	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}
