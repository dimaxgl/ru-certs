package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestLintCSR_Profiles(t *testing.T) {
	// Test Profile DV
	t.Run("DV Profile Valid", func(t *testing.T) {
		res, err := BuildCSR(&CSRConfig{
			Profile:    ProfileDV,
			CommonName: "example.ru",
			SANs:       []string{"example.ru", "www.example.ru"},
			KeyType:    "rsa2048",
		})
		if err != nil {
			t.Fatalf("BuildCSR failed: %v", err)
		}

		report, err := LintCSR(res.CSRPEM)
		if err != nil {
			t.Fatalf("LintCSR failed: %v", err)
		}
		if !report.IsValid {
			t.Errorf("expected valid report, got errors: %v", report.Errors)
		}
		if len(report.Errors) != 0 {
			t.Errorf("expected 0 errors, got %d", len(report.Errors))
		}
		if len(report.SANs) != 2 {
			t.Errorf("expected 2 SANs, got %d", len(report.SANs))
		}
	})

	// Test Profile OV-FL
	t.Run("OV-FL Profile Valid", func(t *testing.T) {
		res, err := BuildCSR(&CSRConfig{
			Profile:    ProfileOVFL,
			CommonName: "fl.example.ru",
			State:      "77 г. Москва",
			Locality:   "Москва",
			Surname:    "Иванов",
			GivenName:  "Иван",
			INN:        "500100732259",
			SNILS:      "112-233-445 95",
			KeyType:    "rsa2048",
		})
		if err != nil {
			t.Fatalf("BuildCSR failed: %v", err)
		}

		report, err := LintCSR(res.CSRPEM)
		if err != nil {
			t.Fatalf("LintCSR failed: %v", err)
		}
		if !report.IsValid {
			t.Errorf("expected valid report, got errors: %v", report.Errors)
		}
	})

	// Test Profile OV-IP
	t.Run("OV-IP Profile Valid", func(t *testing.T) {
		res, err := BuildCSR(&CSRConfig{
			Profile:    ProfileOVIP,
			CommonName: "ip.example.ru",
			State:      "77 г. Москва",
			Locality:   "Москва",
			Surname:    "Иванов",
			GivenName:  "Иван",
			INN:        "500100732259",
			OGRNIP:     "304500116000157",
			SNILS:      "112-233-445 95",
			KeyType:    "rsa2048",
		})
		if err != nil {
			t.Fatalf("BuildCSR failed: %v", err)
		}

		report, err := LintCSR(res.CSRDER)
		if err != nil {
			t.Fatalf("LintCSR with DER failed: %v", err)
		}
		if !report.IsValid {
			t.Errorf("expected valid report, got errors: %v", report.Errors)
		}
	})

	// Test Profile OV-YL
	t.Run("OV-YL Profile Valid", func(t *testing.T) {
		res, err := BuildCSR(&CSRConfig{
			Profile:      ProfileOVYL,
			CommonName:   "corp.example.ru",
			Organization: "ООО Ромашка",
			State:        "77 г. Москва",
			Locality:     "Москва",
			INNLE:        "7707083893",
			OGRN:         "1027700132195",
			KeyType:      "rsa2048",
		})
		if err != nil {
			t.Fatalf("BuildCSR failed: %v", err)
		}

		report, err := LintCSR(res.CSRPEM)
		if err != nil {
			t.Fatalf("LintCSR failed: %v", err)
		}
		if !report.IsValid {
			t.Errorf("expected valid report, got errors: %v", report.Errors)
		}
	})
}

func TestLintCSR_ValidationAndErrors(t *testing.T) {
	t.Run("Missing Country warning and Missing CN error", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				Country: []string{"US"},
				// CommonName is empty
			},
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
		if err != nil {
			t.Fatalf("failed to create CSR: %v", err)
		}

		report, err := LintCSR(der)
		if err != nil {
			t.Fatalf("LintCSR failed: %v", err)
		}
		if report.IsValid {
			t.Errorf("expected report to be invalid due to missing CN")
		}
		if len(report.Warnings) == 0 {
			t.Errorf("expected warning for non-RU country")
		}

		summary := report.FormatSummary()
		if !strings.Contains(summary, "Country (C) should be 'RU'") {
			t.Errorf("expected summary to contain country warning, got %s", summary)
		}
		if !strings.Contains(summary, "CommonName (CN) is missing") {
			t.Errorf("expected summary to contain CN error, got %s", summary)
		}
	})

	t.Run("Invalid OID attributes", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "bad.example.ru",
				Country:    []string{"RU"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: OIDINNLE, Value: "123"},
					{Type: OIDINN, Value: "456"},
					{Type: OIDOGRN, Value: "789"},
					{Type: OIDOGRNIP, Value: "012"},
					{Type: OIDSNILS, Value: "345"},
					{Type: OIDSubjectSignTool, Value: 12345}, // non-string value branch coverage
				},
			},
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
		if err != nil {
			t.Fatalf("failed to create CSR: %v", err)
		}

		report, err := LintCSR(der)
		if err != nil {
			t.Fatalf("LintCSR failed: %v", err)
		}
		if report.IsValid {
			t.Errorf("expected report to be invalid due to bad OID formats")
		}
		if len(report.Errors) < 5 {
			t.Errorf("expected at least 5 errors, got %d", len(report.Errors))
		}

		summary := report.FormatSummary()
		if !strings.Contains(summary, "Errors:") {
			t.Errorf("expected summary to contain Errors section, got %s", summary)
		}
		if !strings.Contains(summary, "Invalid INN LE") {
			t.Errorf("expected summary to mention INN LE error")
		}
	})

	t.Run("Invalid CSR bytes or signature", func(t *testing.T) {
		// Invalid ASN.1 bytes
		_, err := LintCSR([]byte("not-a-csr"))
		if err == nil {
			t.Fatalf("expected error for corrupted CSR bytes, got nil")
		}

		// Broken signature
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "test.ru"},
		}
		der, _ := x509.CreateCertificateRequest(rand.Reader, template, priv)
		// Tamper signature bytes at the end
		tampered := make([]byte, len(der))
		copy(tampered, der)
		tampered[len(tampered)-5] ^= 0xFF

		_, err = LintCSR(tampered)
		if err == nil {
			t.Fatalf("expected error for invalid signature, got nil")
		}
	})
}

func TestFormatSummary_Clean(t *testing.T) {
	report := &LintReport{
		IsValid:   true,
		Subject:   "CN=test.ru,C=RU",
		SANs:      []string{"test.ru"},
		Signature: "SHA256-RSA",
	}
	summary := report.FormatSummary()
	if !strings.Contains(summary, "Valid: true") {
		t.Errorf("expected Valid: true in summary, got:\n%s", summary)
	}
	if strings.Contains(summary, "Errors:") || strings.Contains(summary, "Warnings:") {
		t.Errorf("clean report should not have Errors or Warnings section, got:\n%s", summary)
	}
}
