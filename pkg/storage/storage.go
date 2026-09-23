package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Storage handles local disk storage for certificates and keys
type Storage struct {
	BaseDir string
}

func NewStorage(baseDir string) *Storage {
	if baseDir == "" {
		baseDir = "/etc/ru-certs"
	}
	return &Storage{BaseDir: baseDir}
}

func (s *Storage) AccountsDir() string {
	return filepath.Join(s.BaseDir, "accounts")
}

func (s *Storage) LiveDir(domain string) string {
	return filepath.Join(s.BaseDir, "live", domain)
}

func (s *Storage) ArchiveDir(domain string) string {
	return filepath.Join(s.BaseDir, "archive", domain)
}

func (s *Storage) RenewalDir() string {
	return filepath.Join(s.BaseDir, "renewal")
}

// RenewalConfig tracks renewal metadata for a certificate
type RenewalConfig struct {
	Domain        string    `json:"domain"`
	SANs          []string  `json:"sans,omitempty"`
	ChallengeType string    `json:"challenge_type"`
	WebrootDir    string    `json:"webroot_dir,omitempty"`
	KeyType       string    `json:"key_type"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	CertPath      string    `json:"cert_path"`
	KeyPath       string    `json:"key_path"`
}

// atomicWriteFile writes data to a temporary file in the same directory and renames it atomically
func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, filename)
}

// SaveAccountKey saves an ACME account key securely with 0600 permissions
func (s *Storage) SaveAccountKey(email string, key crypto.Signer) (string, error) {
	if err := os.MkdirAll(s.AccountsDir(), 0700); err != nil {
		return "", err
	}

	keyFile := filepath.Join(s.AccountsDir(), fmt.Sprintf("%s.key", email))
	var keyBytes []byte
	var keyType string

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		var err error
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		keyType = "EC PRIVATE KEY"
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}
	encoded := pem.EncodeToMemory(pemBlock)

	if err := atomicWriteFile(keyFile, encoded, 0600); err != nil {
		return "", err
	}

	return keyFile, nil
}

// LoadOrGenerateAccountKey loads existing account key or creates a new one
func (s *Storage) LoadOrGenerateAccountKey(email string) (crypto.Signer, error) {
	keyFile := filepath.Join(s.AccountsDir(), fmt.Sprintf("%s.key", email))
	if _, err := os.Stat(keyFile); err == nil {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM file")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
			}
			signer, ok := parsed.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("PKCS#8 key is not a crypto.Signer")
			}
			return signer, nil
		}
	}

	// Generate new ECDSA P-256 key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if _, err := s.SaveAccountKey(email, key); err != nil {
		return nil, err
	}
	return key, nil
}

// SaveCertificates atomically writes certs and metadata to disk
func (s *Storage) SaveCertificates(domain string, certChainPEM []byte, privKeyPEM []byte, cfg RenewalConfig) error {
	live := s.LiveDir(domain)
	if err := os.MkdirAll(live, 0755); err != nil {
		return err
	}

	certFile := filepath.Join(live, "fullchain.pem")
	keyFile := filepath.Join(live, "privkey.pem")

	// Write cert atomically
	if err := atomicWriteFile(certFile, certChainPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write key securely & atomically
	if err := atomicWriteFile(keyFile, privKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save renewal config
	if err := os.MkdirAll(s.RenewalDir(), 0755); err != nil {
		return err
	}

	cfg.CertPath = certFile
	cfg.KeyPath = keyFile
	cfgFile := filepath.Join(s.RenewalDir(), fmt.Sprintf("%s.json", domain))
	cfgData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(cfgFile, cfgData, 0644)
}

// ListRenewalConfigs returns all renewal configs
func (s *Storage) ListRenewalConfigs() ([]RenewalConfig, error) {
	dir := s.RenewalDir()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var list []RenewalConfig
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var cfg RenewalConfig
			if err := json.Unmarshal(data, &cfg); err == nil {
				list = append(list, cfg)
			}
		}
	}
	return list, nil
}
