package mock

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/dimaxgl/ru-certs/pkg/acme"
	"github.com/dimaxgl/ru-certs/pkg/csr"
)

func TestMockServerComponents(t *testing.T) {
	srv := NewMockACMEServer()
	defer srv.Close()

	if len(srv.URL()) == 0 {
		t.Errorf("empty server url")
	}

	accKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	client, err := acme.NewClient(srv.URL(), accKey)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	account, err := client.RegisterAccount("mock-test@example.com")
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	if account == nil {
		t.Errorf("nil account")
	}

	order, err := client.CreateOrder([]string{"mock.example.com"})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	if len(order.Authorizations) == 0 {
		t.Fatalf("expected authorizations")
	}

	authz, err := client.FetchAuthorization(order.Authorizations[0])
	if err != nil {
		t.Fatalf("failed to fetch authz: %v", err)
	}

	var httpCh *acme.Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "http-01" {
			httpCh = &authz.Challenges[i]
			break
		}
	}
	if httpCh == nil {
		t.Fatalf("no http-01 challenge found")
	}

	if err := client.TriggerChallenge(httpCh.URL); err != nil {
		t.Fatalf("trigger challenge failed: %v", err)
	}

	csrRes, err := csr.BuildCSR(&csr.CSRConfig{
		Profile:    csr.ProfileDV,
		CommonName: "test.example.com",
	})
	if err != nil {
		t.Fatalf("BuildCSR failed: %v", err)
	}

	finalOrder, err := client.FinalizeOrder(order.Finalize, order.URI, csrRes.CSRDER)
	if err != nil {
		t.Fatalf("FinalizeOrder failed: %v", err)
	}
	if finalOrder.Certificate == "" {
		t.Errorf("empty certificate URL on final order")
	}

	// Download Certificate
	certBundle, err := client.DownloadCertificate(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("DownloadCertificate failed: %v", err)
	}
	if len(certBundle) == 0 {
		t.Errorf("empty cert bundle")
	}
}
