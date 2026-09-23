package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveMultiCert saves certificates for a specific provider in a subfolder (e.g. mintsifry-rsa, letsencrypt, gost)
func (s *Storage) SaveMultiCert(domain, certType string, certPEM, keyPEM []byte) error {
	certDir := filepath.Join(s.BaseDir, "live", domain, certType)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create multi-cert directory: %w", err)
	}

	fullchainPath := filepath.Join(certDir, "fullchain.pem")
	privkeyPath := filepath.Join(certDir, "privkey.pem")

	if err := atomicWriteFile(fullchainPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save multi-cert cert: %w", err)
	}
	if err := atomicWriteFile(privkeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save multi-cert key: %w", err)
	}

	return nil
}
