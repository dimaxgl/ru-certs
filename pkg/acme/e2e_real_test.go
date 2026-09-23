package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

func TestRealEndpointDirectory(t *testing.T) {
	client, err := NewClient(NucAcmeProductionDirectory, nil)
	if err != nil {
		t.Fatalf("failed to connect to real directory: %v", err)
	}

	dir := client.Directory
	t.Logf("Successfully fetched Directory from NUC Voskhod: %+v", dir)

	if dir.NewAccount == "" {
		t.Errorf("expected newAccount URL, got empty")
	}
	if dir.NewOrder == "" {
		t.Errorf("expected newOrder URL, got empty")
	}
	if dir.NewNonce == "" {
		t.Errorf("expected newNonce URL, got empty")
	}
}

func TestRealEndpointNonce(t *testing.T) {
	client, err := NewClient(NucAcmeProductionDirectory, nil)
	if err != nil {
		t.Fatalf("failed to connect to real directory: %v", err)
	}
	nonce, err := client.GetNonce()
	if err != nil {
		t.Fatalf("failed to fetch nonce from real endpoint: %v", err)
	}
	t.Logf("Got replay nonce from NUC Voskhod: %s", nonce)
	if nonce == "" {
		t.Errorf("expected nonce string, got empty")
	}
}

func TestRealEndpointAccountRegistrationAndOrder(t *testing.T) {
	if os.Getenv("RUN_REAL_ACME_MUTATING") != "1" {
		t.Skip("Skipping mutating real ACME account/order test. Set RUN_REAL_ACME_MUTATING=1 to run against production CA.")
	}

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	client, err := NewClient(NucAcmeProductionDirectory, accountKey)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	contactEmail := "test-acme-dev@example.ru"
	t.Logf("Registering account on real NUC Voskhod ACME with email: %s", contactEmail)
	acc, err := client.RegisterAccount(contactEmail)
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	t.Logf("Account registered successfully: URL=%s Status=%s", acc.URI, acc.Status)

	sampleDomain := "test-validation.ru"
	t.Logf("Creating ACME order for sample domain %s...", sampleDomain)
	order, err := client.CreateOrder([]string{sampleDomain})
	if err != nil {
		t.Fatalf("failed to create order on real NUC Voskhod CA: %v", err)
	}

	t.Logf("Order created: URL=%s, Status=%s, Authorizations=%v", order.URI, order.Status, order.Authorizations)

	if len(order.Authorizations) > 0 {
		authz, err := client.FetchAuthorization(order.Authorizations[0])
		if err != nil {
			t.Fatalf("failed to fetch authorization: %v", err)
		}
		t.Logf("Authorization status: %s for %s", authz.Status, authz.Identifier.Value)
		for _, ch := range authz.Challenges {
			t.Logf(" - Challenge type: %s, URL: %s, token: %s", ch.Type, ch.URL, ch.Token)
		}
	}
}
