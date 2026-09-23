package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStorage(tempDir)

	key, err := store.LoadOrGenerateAccountKey("admin@example.com")
	if err != nil {
		t.Fatalf("LoadOrGenerateAccountKey failed: %v", err)
	}

	keyFile := filepath.Join(store.AccountsDir(), "admin@example.com.key")
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 perm, got %o", info.Mode().Perm())
	}

	key2, err := store.LoadOrGenerateAccountKey("admin@example.com")
	if err != nil {
		t.Fatalf("reload account key failed: %v", err)
	}
	if key.Public() == nil || key2.Public() == nil {
		t.Errorf("invalid public keys")
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = rsaKey

	cfg := RenewalConfig{
		Domain:        "example.ru",
		ChallengeType: "http-01",
		KeyType:       "rsa",
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
	}

	err = store.SaveCertificates("example.ru", []byte("CERT DATA"), []byte("KEY DATA"), cfg)
	if err != nil {
		t.Fatalf("SaveCertificates failed: %v", err)
	}

	// Save existing cert again to test archive version increment
	cfg2 := cfg
	cfg2.Domain = "example.ru"
	err = store.SaveCertificates("example.ru", []byte("CERT DATA V2"), []byte("KEY DATA V2"), cfg2)
	if err != nil {
		t.Fatalf("SaveCertificates v2 failed: %v", err)
	}

	cfgs, err := store.ListRenewalConfigs()
	if err != nil {
		t.Fatalf("ListRenewalConfigs failed: %v", err)
	}
	if len(cfgs) != 1 || cfgs[0].Domain != "example.ru" {
		t.Errorf("unexpected configs: %+v", cfgs)
	}

	if store.ArchiveDir("example.ru") != filepath.Join(tempDir, "archive", "example.ru") {
		t.Errorf("unexpected ArchiveDir")
	}

	// Test default base dir when empty
	defaultStore := NewStorage("")
	if defaultStore.BaseDir != "/etc/ru-certs" {
		t.Errorf("expected /etc/ru-certs default base dir, got %s", defaultStore.BaseDir)
	}

	// Test SaveAccountKey with ecdsa key
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := store.SaveAccountKey("ec@example.com", ecKey); err != nil {
		t.Fatalf("failed to save ECDSA account key: %v", err)
	}
	loadedEcKey, err := store.LoadOrGenerateAccountKey("ec@example.com")
	if err != nil {
		t.Fatalf("failed to load ECDSA account key: %v", err)
	}
	if loadedEcKey.Public() == nil {
		t.Errorf("expected valid ECDSA key")
	}

	// Test corrupt account key file handling
	corruptFile := filepath.Join(store.AccountsDir(), "corrupt@example.com.key")
	_ = os.WriteFile(corruptFile, []byte("NOT PEM DATA"), 0600)
	if _, err := store.LoadOrGenerateAccountKey("corrupt@example.com"); err == nil {
		t.Errorf("expected error loading corrupted key")
	}

	// Test corrupted renewal file handling
	badRenewalFile := filepath.Join(store.RenewalDir(), "corrupt.json")
	_ = os.WriteFile(badRenewalFile, []byte("NOT JSON"), 0644)
	// Create a sub directory in renewal dir to test non-file / skip non-json
	_ = os.Mkdir(filepath.Join(store.RenewalDir(), "subdir.json"), 0755)
	_ = os.WriteFile(filepath.Join(store.RenewalDir(), "ignore.txt"), []byte("ignore"), 0644)

	cfgsAfterBad, err := store.ListRenewalConfigs()
	if err != nil {
		t.Fatalf("ListRenewalConfigs should skip bad files, got error: %v", err)
	}
	if len(cfgsAfterBad) != 1 {
		t.Errorf("expected 1 valid renewal config, got %d", len(cfgsAfterBad))
	}

	// Test SaveAccountKey with unsupported key type
	type unsupportedKey struct{ crypto.Signer }
	if _, err := store.SaveAccountKey("unsupported@example.com", unsupportedKey{}); err == nil {
		t.Errorf("expected error for unsupported key type")
	}
}
