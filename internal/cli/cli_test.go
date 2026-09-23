package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaxgl/ru-certs/internal/cli"
)

func TestCLICSRCommand(t *testing.T) {
	tmpDir := t.TempDir()
	outCSR := filepath.Join(tmpDir, "test.csr")

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{
		"csr",
		"--profile", "dv",
		"--cn", "my-domain.ru",
		"-d", "my-domain.ru",
		"-d", "www.my-domain.ru",
		"--output", outCSR,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI csr command failed: %v", err)
	}

	if _, err := os.Stat(outCSR); err != nil {
		t.Fatalf("expected CSR file to be generated at %s", outCSR)
	}
	if _, err := os.Stat(outCSR + ".key"); err != nil {
		t.Fatalf("expected Key file to be generated at %s", outCSR+".key")
	}
}

func TestCLICAExportCommand(t *testing.T) {
	tmpDir := t.TempDir()
	outBundle := filepath.Join(tmpDir, "ca.pem")

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{
		"ca", "export",
		outBundle,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI ca export command failed: %v", err)
	}

	data, err := os.ReadFile(outBundle)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected exported bundle not to be empty")
	}
}
