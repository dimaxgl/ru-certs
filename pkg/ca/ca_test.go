package ca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergedBundle(t *testing.T) {
	bundle := GetMergedBundle()
	if len(bundle) == 0 {
		t.Fatalf("bundle is empty")
	}

	tmpFile := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := ExportToFile(tmpFile, true); err != nil {
		t.Fatalf("ExportToFile failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read exported bundle: %v", err)
	}

	if len(data) != len(bundle) {
		t.Errorf("size mismatch: expected %d, got %d", len(bundle), len(data))
	}

	tmpRoot := filepath.Join(t.TempDir(), "ca-root.pem")
	if err := ExportToFile(tmpRoot, false); err != nil {
		t.Fatalf("ExportToFile without sub failed: %v", err)
	}
	rootData, err := os.ReadFile(tmpRoot)
	if err != nil {
		t.Fatalf("failed to read exported root: %v", err)
	}
	if len(rootData) != len(RussianTrustedRootCA) {
		t.Errorf("root size mismatch: expected %d, got %d", len(RussianTrustedRootCA), len(rootData))
	}
}

func TestInstallDryRun(t *testing.T) {
	out, err := InstallToSystemStore(true)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if len(out) == 0 {
		t.Errorf("expected dry run message, got empty")
	}
}
