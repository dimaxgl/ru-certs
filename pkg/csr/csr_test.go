package csr

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestValidators(t *testing.T) {
	// Test Valid INN LE (10 digits) - Sberbank INN: 7707083893
	if err := ValidateINN10("7707083893"); err != nil {
		t.Errorf("expected valid INN10, got: %v", err)
	}
	if err := ValidateINN10("7707083894"); err == nil {
		t.Errorf("expected invalid INN10 checksum to fail")
	}

	// Test Valid OGRN (13 digits) - Sberbank OGRN: 1027700132195
	if err := ValidateOGRN("1027700132195"); err != nil {
		t.Errorf("expected valid OGRN, got: %v", err)
	}
	if err := ValidateOGRN("1027700132194"); err == nil {
		t.Errorf("expected invalid OGRN checksum to fail")
	}

	// Test Valid OGRNIP (15 digits) - e.g. 304770000123456
	// Let's compute a valid 15-digit OGRNIP: 30477000012345 -> num % 13 % 10
	var num int64 = 30477000012345
	chk := int(num % 13 % 10)
	ogrnip := "30477000012345" + string('0'+byte(chk))
	if err := ValidateOGRNIP(ogrnip); err != nil {
		t.Errorf("expected valid OGRNIP %s, got: %v", ogrnip, err)
	}

	// Test SNILS
	// 112-233-445 95 -> 1*9 + 1*8 + 2*7 + 2*6 + 3*5 + 3*4 + 4*3 + 4*2 + 5*1 = 9+8+14+12+15+12+12+8+5 = 95
	if err := ValidateSNILS("11223344595"); err != nil {
		t.Errorf("expected valid SNILS, got: %v", err)
	}

	// Test ST Format
	if err := ValidateST("77 г. Москва"); err != nil {
		t.Errorf("expected valid ST, got: %v", err)
	}
	if err := ValidateST("Москва"); err == nil {
		t.Errorf("expected invalid ST without region code to fail")
	}

	// Test Punycode
	puny, err := ToPunycode("тест.рф")
	if err != nil {
		t.Fatalf("unexpected punycode error: %v", err)
	}
	if puny != "xn--e1aybc.xn--p1ai" {
		t.Errorf("expected xn--e1aybc.xn--p1ai, got %s", puny)
	}
}

func TestBuildCSR_DV(t *testing.T) {
	cfg := &CSRConfig{
		Profile:    ProfileDV,
		CommonName: "example.ru",
		SANs:       []string{"example.ru", "www.example.ru"},
		KeyType:    "rsa2048",
	}

	res, err := BuildCSR(cfg)
	if err != nil {
		t.Fatalf("failed to build DV CSR: %v", err)
	}

	if len(res.PrivateKeyPEM) == 0 || len(res.CSRPEM) == 0 {
		t.Fatalf("missing PEM outputs")
	}

	block, _ := pem.Decode(res.CSRPEM)
	if block == nil {
		t.Fatalf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "example.ru" {
		t.Errorf("expected CN example.ru, got %s", csr.Subject.CommonName)
	}

	if len(csr.DNSNames) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(csr.DNSNames))
	}
}

func TestBuildCSR_OVYL(t *testing.T) {
	cfg := &CSRConfig{
		Profile:         ProfileOVYL,
		CommonName:      "portal.sberbank.ru",
		SANs:            []string{"portal.sberbank.ru"},
		KeyType:         "rsa2048",
		Organization:    "ПАО СБЕРБАНК",
		INNLE:           "7707083893",
		OGRN:            "1027700132195",
		State:           "77 г. Москва",
		Locality:        "г. Москва",
		Street:          "ул. Вавилова, д. 19",
		SKZIClass:       SKZIKC1,
		SubjectSignTool: "СКЗИ \"КриптоПро CSP\"",
	}

	res, err := BuildCSR(cfg)
	if err != nil {
		t.Fatalf("failed to build OV-YL CSR: %v", err)
	}

	report, err := LintCSR(res.CSRPEM)
	if err != nil {
		t.Fatalf("LintCSR failed: %v", err)
	}

	if !report.IsValid {
		t.Fatalf("expected valid report, errors: %v", report.Errors)
	}
}

func TestBuildCSR_AdditionalProfilesAndErrors(t *testing.T) {
	// Test nil config
	if _, err := BuildCSR(nil); err == nil {
		t.Errorf("expected error for nil config")
	}

	// Test invalid profile
	if _, err := BuildCSR(&CSRConfig{Profile: "invalid-profile"}); err == nil {
		t.Errorf("expected error for invalid profile")
	}

	// Test DV empty CN
	if _, err := BuildCSR(&CSRConfig{Profile: ProfileDV, CommonName: ""}); err == nil {
		t.Errorf("expected error for DV with empty CN")
	}

	// Test OV-FL empty names
	if _, err := BuildCSR(&CSRConfig{Profile: ProfileOVFL, CommonName: "test.ru"}); err == nil {
		t.Errorf("expected error for OV-FL missing surname/givenName")
	}

	// Test OV-IP empty names
	if _, err := BuildCSR(&CSRConfig{Profile: ProfileOVIP, CommonName: "test.ru"}); err == nil {
		t.Errorf("expected error for OV-IP missing surname/givenName")
	}

	// Test OV-YL empty organization
	if _, err := BuildCSR(&CSRConfig{Profile: ProfileOVYL, CommonName: "test.ru"}); err == nil {
		t.Errorf("expected error for OV-YL missing organization")
	}

	// Test key types
	for _, kt := range []string{"rsa4096", "ecdsa-p256", "ecdsa"} {
		res, err := BuildCSR(&CSRConfig{
			Profile:    ProfileDV,
			CommonName: "test.ru",
			KeyType:    kt,
			SKZIClass:  SKZIKC2,
		})
		if err != nil {
			t.Fatalf("failed to build CSR with keyType %s: %v", kt, err)
		}
		if len(res.CSRPEM) == 0 {
			t.Errorf("expected non-empty CSR for %s", kt)
		}
	}

	// Test invalid key type
	if _, err := BuildCSR(&CSRConfig{Profile: ProfileDV, CommonName: "test.ru", KeyType: "invalid-key-algo"}); err == nil {
		t.Errorf("expected error for invalid key type")
	}

	// Test IP address as CN and SANs
	resIP, err := BuildCSR(&CSRConfig{
		Profile:    ProfileDV,
		CommonName: "192.168.1.1",
		SANs:       []string{"192.168.1.1", "10.0.0.1"},
		KeyType:    "rsa2048",
	})
	if err != nil {
		t.Fatalf("failed to build CSR with IP SANs: %v", err)
	}
	if len(resIP.CSRPEM) == 0 {
		t.Errorf("expected non-empty CSR for IP SANs")
	}

	// Test all SKZI Classes
	for _, skzi := range []SKZIClass{SKZIKC3, SKZIKB1, SKZIKB2} {
		resSKZI, err := BuildCSR(&CSRConfig{
			Profile:    ProfileDV,
			CommonName: "test.ru",
			SKZIClass:  skzi,
		})
		if err != nil {
			t.Fatalf("failed to build CSR with SKZI %s: %v", skzi, err)
		}
		if len(resSKZI.CSRPEM) == 0 {
			t.Errorf("expected non-empty CSR for SKZI %s", skzi)
		}
	}
}
