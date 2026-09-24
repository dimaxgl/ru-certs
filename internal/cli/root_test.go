package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaxgl/ru-certs/pkg/storage"
)

func generateTestCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

func TestCLIRoot_HelpAndBasics(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected --help to succeed, got: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "ru-certs") {
		t.Errorf("expected help output to contain 'ru-certs', got: %s", output)
	}
}

func TestCLICSR_ProfilesAndFlags(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("DV Profile to stdout", func(t *testing.T) {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{
			"csr",
			"--profile", "dv",
			"--cn", "site.ru",
			"-d", "site.ru,www.site.ru",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	})

	t.Run("OV-YL Profile with full OIDs to file", func(t *testing.T) {
		outCSR := filepath.Join(tmpDir, "ov_yl.csr")
		cmd := NewRootCmd()
		cmd.SetArgs([]string{
			"csr",
			"--profile", "ov-yl",
			"--cn", "corp.ru",
			"--org", "Test Company LLC",
			"--inn-le", "7707083893",
			"--ogrn", "1027700132195",
			"--snils", "11223344595",
			"--surname", "Иванов",
			"--given-name", "Иван Иванович",
			"--title", "Генеральный директор",
			"--state", "77 г. Москва",
			"--loc", "г. Москва",
			"--street", "ул. Тверская, д. 1",
			"--email", "admin@corp.ru",
			"--skzi-class", "KC2",
			"--sign-tool", "CryptoPro CSP",
			"--key-type", "rsa2048",
			"-o", outCSR,
		})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}

		if _, err := os.Stat(outCSR); err != nil {
			t.Errorf("expected csr file %s to exist", outCSR)
		}
		if _, err := os.Stat(outCSR + ".key"); err != nil {
			t.Errorf("expected key file %s to exist", outCSR+".key")
		}
	})

	t.Run("Invalid CSR config returns error", func(t *testing.T) {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{
			"csr",
			"--profile", "ov-yl",
			"--cn", "invalid.ru",
			// Missing required fields
		})
		if err := cmd.Execute(); err == nil {
			t.Fatal("expected error for invalid CSR configuration, got nil")
		}
	})
}

func TestCLICA_Commands(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("CA install dry-run", func(t *testing.T) {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{
			"ca", "install",
			"--dry-run",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected ca install --dry-run to succeed, got: %v", err)
		}
	})

	t.Run("CA export missing output arg", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{
			"ca", "export",
		})
		if err := cmd.Execute(); err == nil {
			t.Fatal("expected error when output argument is missing, got nil")
		}
	})

	t.Run("CA export success", func(t *testing.T) {
		outPath := filepath.Join(tmpDir, "exported-ca.pem")
		cmd := NewRootCmd()
		cmd.SetArgs([]string{
			"ca", "export",
			outPath,
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected ca export to succeed, got: %v", err)
		}
		if _, err := os.Stat(outPath); err != nil {
			t.Fatalf("expected file %s to exist", outPath)
		}
	})
}

func TestCLIRenew_Commands(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Empty renewal storage", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{
			"--config-dir", tmpDir,
			"renew",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected renew to handle empty storage, got: %v", err)
		}
	})

	t.Run("With existing certificates due and not due", func(t *testing.T) {
		store := storage.NewStorage(tmpDir)
		certPEM, keyPEM := generateTestCertPEM(t)

		// 1. Certificate expiring soon (10 days)
		cfgDue := storage.RenewalConfig{
			Domain:        "due.example.com",
			IssuedAt:      time.Now().Add(-80 * 24 * time.Hour),
			ExpiresAt:     time.Now().Add(10 * 24 * time.Hour),
			ChallengeType: "http-01",
		}
		if err := store.SaveCertificates("due.example.com", certPEM, keyPEM, cfgDue); err != nil {
			t.Fatalf("failed to save due cert: %v", err)
		}

		// 2. Certificate fresh (80 days remaining)
		cfgFresh := storage.RenewalConfig{
			Domain:        "fresh.example.com",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(80 * 24 * time.Hour),
			ChallengeType: "http-01",
		}
		if err := store.SaveCertificates("fresh.example.com", certPEM, keyPEM, cfgFresh); err != nil {
			t.Fatalf("failed to save fresh cert: %v", err)
		}

		// Normal run (should check both)
		cmd := NewRootCmd()
		cmd.SetArgs([]string{
			"--config-dir", tmpDir,
			"renew",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("renew failed: %v", err)
		}

		// Force renew run
		cmdForce := NewRootCmd()
		cmdForce.SetArgs([]string{
			"--config-dir", tmpDir,
			"renew",
			"--force",
		})
		if err := cmdForce.Execute(); err != nil {
			t.Fatalf("force renew failed: %v", err)
		}
	})
}

func TestCLICert_FlagValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// Lightweight mock server to avoid dialing default external server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "nonce-flag-test")
		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"newNonce": "http://` + r.Host + `/new-nonce",
				"newAccount": "http://` + r.Host + `/new-account",
				"newOrder": "http://` + r.Host + `/new-order"
			}`))
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", "http://"+r.Host+"/accounts/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status": "valid"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tests := []struct {
		name      string
		args      []string
		errSubstr string
	}{
		{
			name: "missing domains",
			args: []string{
				"--config-dir", tmpDir,
				"--server", ts.URL + "/directory",
				"--email", "admin@example.com",
				"cert", "obtain",
			},
			errSubstr: "at least one domain",
		},
		{
			name: "dns-01 regru branch flag validation",
			args: []string{
				"--config-dir", tmpDir,
				"--server", "http://127.0.0.1:54321/directory",
				"--email", "admin@example.com",
				"cert", "obtain",
				"-d", "example.com",
				"--dns", "regru",
				"--regru-user", "u",
				"--regru-password", "p",
			},
			errSubstr: "connection refused",
		},
		{
			name: "dns-01 cloudflare branch flag validation",
			args: []string{
				"--config-dir", tmpDir,
				"--server", "http://127.0.0.1:54321/directory",
				"--email", "admin@example.com",
				"cert", "obtain",
				"-d", "example.com",
				"--dns", "cloudflare",
				"--cf-token", "tok",
			},
			errSubstr: "connection refused",
		},
		{
			name: "dns-01 cf alias flag validation",
			args: []string{
				"--config-dir", tmpDir,
				"--server", "http://127.0.0.1:54321/directory",
				"--email", "admin@example.com",
				"cert", "obtain",
				"-d", "example.com",
				"--dns", "cf",
				"--cf-key", "k",
				"--cf-email", "e@example.com",
			},
			errSubstr: "connection refused",
		},
		{
			name: "missing email",
			args: []string{
				"--config-dir", tmpDir,
				"--server", ts.URL + "/directory",
				"cert", "obtain",
				"-d", "example.com",
			},
			errSubstr: "email must be specified",
		},
		{
			name: "missing challenge provider",
			args: []string{
				"--config-dir", tmpDir,
				"--server", ts.URL + "/directory",
				"--email", "admin@example.com",
				"cert", "obtain",
				"-d", "example.com",
			},
			errSubstr: "a challenge method must be specified",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("expected error %q to contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

func TestCLICert_ObtainWithMockACMEServer(t *testing.T) {
	tmpDir := t.TempDir()
	webrootDir := filepath.Join(tmpDir, "www")
	os.MkdirAll(webrootDir, 0755)

	certPEM, _ := generateTestCertPEM(t)

	var srvURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "nonce-12345")

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"newNonce": "` + srvURL + `/new-nonce",
				"newAccount": "` + srvURL + `/new-account",
				"newOrder": "` + srvURL + `/new-order"
			}`))
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", srvURL+"/accounts/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status": "valid", "contact": ["mailto:admin@example.com"]}`))
		case "/new-order":
			w.Header().Set("Location", srvURL+"/orders/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{
				"status": "pending",
				"authorizations": ["` + srvURL + `/authz/1"],
				"finalize": "` + srvURL + `/orders/1/finalize",
				"certificate": "` + srvURL + `/certs/1"
			}`))
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "valid",
				"identifier": {"type": "dns", "value": "test.example.com"},
				"challenges": [
					{
						"type": "http-01",
						"url": "` + srvURL + `/chall/1",
						"token": "token123"
					}
				]
			}`))
		case "/orders/1/finalize":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "valid",
				"certificate": "` + srvURL + `/certs/1"
			}`))
		case "/certs/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			w.Write(certPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srvURL = ts.URL

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config-dir", tmpDir,
		"--server", srvURL + "/directory",
		"--email", "admin@example.com",
		"cert", "obtain",
		"-d", "test.example.com",
		"--webroot", webrootDir,
		"--key-type", "ecdsa-p256",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert obtain failed: %v", err)
	}

	liveCert := filepath.Join(tmpDir, "live", "test.example.com", "fullchain.pem")
	if _, err := os.Stat(liveCert); err != nil {
		t.Errorf("expected live certificate at %s", liveCert)
	}
}
