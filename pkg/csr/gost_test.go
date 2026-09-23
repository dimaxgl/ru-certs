package csr

import (
	"encoding/asn1"
	"testing"
)

func TestGOSTKeyGeneration(t *testing.T) {
	key256, err := GenerateGOSTKey(256)
	if err != nil {
		t.Fatalf("GenerateGOSTKey(256) failed: %v", err)
	}
	if key256.CurveSize != 256 || key256.Prv == nil {
		t.Fatalf("invalid 256-bit key structure")
	}

	pemData256 := key256.EncodePrivatePEM()
	if len(pemData256) == 0 {
		t.Errorf("expected PEM encoded key, got empty")
	}

	key512, err := GenerateGOSTKey(512)
	if err != nil {
		t.Fatalf("GenerateGOSTKey(512) failed: %v", err)
	}
	if key512.CurveSize != 512 || key512.Prv == nil {
		t.Fatalf("invalid 512-bit key structure")
	}
}

func TestBuildGOSTCSR_256_and_512(t *testing.T) {
	req := &CSRConfig{
		Profile:         ProfileOVYL,
		CommonName:      "гост-портал.рф",
		Organization:    "ООО РОССИЙСКИЕ ТЕХНОЛОГИИ",
		INNLE:           "7701234560",
		OGRN:            "1237700123451",
		State:           "77 г. Москва",
		Locality:        "г. Москва",
		Street:          "ул. Тверская, д. 1",
		SKZIClass:       SKZIKC1,
		SubjectSignTool: "СКЗИ КриптоПро CSP (версия 5.0)",
	}

	// 1. Build GOST 2012 256-bit CSR
	key256, err := GenerateGOSTKey(256)
	if err != nil {
		t.Fatalf("failed to generate 256 key: %v", err)
	}
	res256, err := BuildGOSTCSR(req, key256)
	if err != nil {
		t.Fatalf("BuildGOSTCSR(256) failed: %v", err)
	}
	if len(res256.CSRDER) == 0 || len(res256.CSRPEM) == 0 {
		t.Fatalf("empty DER or PEM output for 256 CSR")
	}

	var parsed256 certificationRequest
	if _, err := asn1.Unmarshal(res256.CSRDER, &parsed256); err != nil {
		t.Fatalf("failed to unmarshal generated GOST 256 CSR: %v", err)
	}
	if !parsed256.SignatureAlgorithm.Algorithm.Equal(OIDSignatureGOST3410_2012_256) {
		t.Errorf("expected signature OID %v, got %v", OIDSignatureGOST3410_2012_256, parsed256.SignatureAlgorithm.Algorithm)
	}

	// 2. Build GOST 2012 512-bit CSR
	key512, err := GenerateGOSTKey(512)
	if err != nil {
		t.Fatalf("failed to generate 512 key: %v", err)
	}
	res512, err := BuildGOSTCSR(req, key512)
	if err != nil {
		t.Fatalf("BuildGOSTCSR(512) failed: %v", err)
	}
	if len(res512.CSRDER) == 0 || len(res512.CSRPEM) == 0 {
		t.Fatalf("empty DER or PEM output for 512 CSR")
	}

	var parsed512 certificationRequest
	if _, err := asn1.Unmarshal(res512.CSRDER, &parsed512); err != nil {
		t.Fatalf("failed to unmarshal generated GOST 512 CSR: %v", err)
	}
	if !parsed512.SignatureAlgorithm.Algorithm.Equal(OIDSignatureGOST3410_2012_512) {
		t.Errorf("expected signature OID %v, got %v", OIDSignatureGOST3410_2012_512, parsed512.SignatureAlgorithm.Algorithm)
	}
}
