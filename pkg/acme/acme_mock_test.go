package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/dimaxgl/ru-certs/pkg/acme/mock"
)

func TestMockACMEFullOrderFlow(t *testing.T) {
	mockServer := mock.NewMockACMEServer()
	defer mockServer.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	client, err := NewClient(mockServer.URL(), key)
	if err != nil {
		t.Fatalf("failed to create ACME client with mock: %v", err)
	}

	acc, err := client.RegisterAccount("admin@test.ru")
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	if acc == nil || acc.URI == "" {
		t.Fatalf("expected non-empty account URI")
	}

	order, err := client.CreateOrder([]string{"example.ru"})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}
	if len(order.Authorizations) == 0 {
		t.Fatalf("expected authorizations in order")
	}

	authz, err := client.FetchAuthorization(order.Authorizations[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}

	var httpChall *Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			httpChall = &ch
			break
		}
	}
	if httpChall == nil {
		t.Fatalf("expected http-01 challenge")
	}

	if err := client.TriggerChallenge(httpChall.URL); err != nil {
		t.Fatalf("failed to trigger challenge: %v", err)
	}

	csrDER := []byte("dummy-csr-der-bytes")
	finalOrder, err := client.FinalizeOrder(order.Finalize, order.URI, csrDER)
	if err != nil {
		t.Fatalf("failed to finalize order: %v", err)
	}

	if finalOrder.Certificate == "" {
		t.Fatalf("expected certificate URL in finalized order")
	}

	certBytes, err := client.DownloadCertificate(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("failed to download certificate: %v", err)
	}

	if len(certBytes) == 0 {
		t.Errorf("expected non-empty cert bytes")
	}
}
