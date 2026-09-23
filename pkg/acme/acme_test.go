package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWSandKeyAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}

	token := "dummy_token_12345"
	ka, err := KeyAuthorization(token, key)
	if err != nil {
		t.Fatalf("key auth failed: %v", err)
	}
	if len(ka) == 0 {
		t.Errorf("empty key authorization")
	}

	dnsVal, err := KeyAuthorizationSHA256(token, key)
	if err != nil {
		t.Fatalf("key auth sha256 failed: %v", err)
	}
	if len(dnsVal) == 0 {
		t.Errorf("empty dns sha256 value")
	}

	signed, err := SignJWS(key, "", "https://example.com/acme/order", "nonce_abc", []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("SignJWS failed: %v", err)
	}
	if len(signed) == 0 {
		t.Errorf("empty JWS payload")
	}
}

func TestACMEClientDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"newNonce": "http://example.com/acme/new-nonce",
			"newAccount": "http://example.com/acme/new-account",
			"newOrder": "http://example.com/acme/new-order"
		}`))
	}))
	defer srv.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	client, err := NewClient(srv.URL, key)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.Directory.NewOrder != "http://example.com/acme/new-order" {
		t.Errorf("unexpected directory newOrder endpoint: %s", client.Directory.NewOrder)
	}

	// Test ECDSA SignJWS and thumbprint
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kaEc, err := KeyAuthorization("token_ec", ecKey)
	if err != nil {
		t.Fatalf("KeyAuthorization failed with ecdsa key: %v", err)
	}
	if len(kaEc) == 0 {
		t.Errorf("empty ec key authorization")
	}

	signedEc, err := SignJWS(ecKey, "kid_ec", "https://example.com/acme/new-order", "nonce_ec", []byte(`{"contact":["mailto:a@b.com"]}`))
	if err != nil {
		t.Fatalf("SignJWS failed with ecdsa key: %v", err)
	}
	if len(signedEc) == 0 {
		t.Errorf("empty ec signed JWS")
	}

	// Test nil/unsupported
	if _, err := JWKThumbprint("invalid-pub-key"); err == nil {
		t.Errorf("expected error for invalid public key")
	}
}
