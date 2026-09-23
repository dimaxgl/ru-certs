package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cfRoundTripper struct {
	handler http.HandlerFunc
}

func (rt *cfRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.handler(rec, req)
	return rec.Result(), nil
}

func TestCloudflareProvider_FullLifecycle_TokenAuth(t *testing.T) {
	createdRecords := make(map[string]string)
	deletedRecords := make(map[string]bool)

	handler := func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-token" {
			http.Error(w, `{"success":false,"errors":[{"message":"unauthorized"}]}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// 1. Zone lookup
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/client/v4/zones") {
			name := r.URL.Query().Get("name")
			if name == "example.com" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"success": true,
					"result": [
						{"id": "zone-12345", "name": "example.com"}
					]
				}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "result": []}`))
			return
		}

		// 2. Create DNS Record
		if r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-12345/dns_records" {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			json.Unmarshal(body, &payload)

			recordName := payload["name"].(string)
			recordID := "rec-" + recordName
			createdRecords[recordName] = recordID

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"success": true,
				"result": {"id": "` + recordID + `"}
			}`))
			return
		}

		// 3. Delete DNS Record
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/client/v4/zones/zone-12345/dns_records/") {
			recID := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone-12345/dns_records/")
			deletedRecords[recID] = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "result": {"id": "` + recID + `"}}`))
			return
		}

		http.NotFound(w, r)
	}

	p := NewCloudflareProvider("test-token", "", "")
	p.HTTPClient.Transport = &cfRoundTripper{handler: handler}

	domain := "sub.example.com"
	token := "token-abc"
	keyAuth := "token-abc.secret"

	// Present challenge
	err := p.Present(domain, token, keyAuth)
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	expectedRecordName := "_acme-challenge.sub.example.com"
	expectedRecordID := "rec-" + expectedRecordName
	if createdRecords[expectedRecordName] != expectedRecordID {
		t.Errorf("record was not recorded as created: %+v", createdRecords)
	}

	// Verify internal map has composite key
	compKey := expectedRecordName + ":" + token
	p.mu.Lock()
	id, exists := p.recordIDs[compKey]
	p.mu.Unlock()
	if !exists || id != expectedRecordID {
		t.Errorf("expected composite key %q to have ID %q, got exists=%v id=%q", compKey, expectedRecordID, exists, id)
	}

	// CleanUp challenge
	err = p.CleanUp(domain, token, keyAuth)
	if err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}

	if !deletedRecords[expectedRecordID] {
		t.Errorf("expected record %q to be deleted", expectedRecordID)
	}

	// Verify key was cleaned up from map
	p.mu.Lock()
	_, stillExists := p.recordIDs[compKey]
	p.mu.Unlock()
	if stillExists {
		t.Errorf("expected composite key %q to be deleted from state", compKey)
	}

	// Second cleanup should be a no-op (key no longer exists)
	if err := p.CleanUp(domain, token, keyAuth); err != nil {
		t.Errorf("expected idempotent cleanup, got error: %v", err)
	}
}

func TestCloudflareProvider_APIKeyAndEmailAuth(t *testing.T) {
	var capturedKey, capturedEmail string

	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("X-Auth-Key")
		capturedEmail = r.Header.Get("X-Auth-Email")

		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/client/v4/zones") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"success": true,
				"result": [{"id": "z1", "name": "example.org"}]
			}`))
			return
		}
		http.NotFound(w, r)
	}

	p := NewCloudflareProvider("", "my-api-key", "my-email@example.com")
	p.HTTPClient.Transport = &cfRoundTripper{handler: handler}

	zoneID, err := p.findZoneID("example.org")
	if err != nil {
		t.Fatalf("findZoneID failed: %v", err)
	}
	if zoneID != "z1" {
		t.Errorf("expected zoneID 'z1', got %q", zoneID)
	}
	if capturedKey != "my-api-key" || capturedEmail != "my-email@example.com" {
		t.Errorf("expected auth headers X-Auth-Key / X-Auth-Email, got key=%q email=%q", capturedKey, capturedEmail)
	}
}

func TestCloudflareProvider_NoAuthCredentials(t *testing.T) {
	p := NewCloudflareProvider("", "", "")
	err := p.Present("example.com", "token", "token.auth")
	if err == nil {
		t.Fatal("expected error when no auth credentials provided")
	}
	if !strings.Contains(err.Error(), "must be provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCloudflareProvider_ZoneNotFound(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "result": []}`))
	}

	p := NewCloudflareProvider("token", "", "")
	p.HTTPClient.Transport = &cfRoundTripper{handler: handler}

	err := p.Present("nonexistent.domain.ru", "token", "token.auth")
	if err == nil {
		t.Fatal("expected error for nonexistent zone, got nil")
	}
	if !strings.Contains(err.Error(), "cloudflare zone not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCloudflareProvider_CreateRecordError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/client/v4/zones") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "result": [{"id": "z1", "name": "example.com"}]}`))
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{
				"success": false,
				"errors": [
					{"message": "record already exists"},
					{"message": "rate limit exceeded"}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}

	p := NewCloudflareProvider("token", "", "")
	p.HTTPClient.Transport = &cfRoundTripper{handler: handler}

	err := p.Present("example.com", "token", "token.auth")
	if err == nil {
		t.Fatal("expected error on DNS record creation failure")
	}
	if !strings.Contains(err.Error(), "record already exists") || !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("error did not aggregate error messages: %v", err)
	}
}

func TestCloudflareProvider_WildcardDomainHandling(t *testing.T) {
	var requestedZoneNames []string
	var createdRecordName string

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/client/v4/zones") {
			name := r.URL.Query().Get("name")
			requestedZoneNames = append(requestedZoneNames, name)
			if name == "wildcard.org" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"success": true, "result": [{"id": "zwild", "name": "wildcard.org"}]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "result": []}`))
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			json.Unmarshal(body, &payload)
			createdRecordName = payload["name"].(string)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "result": {"id": "rec-wild"}}`))
			return
		}
		http.NotFound(w, r)
	}

	p := NewCloudflareProvider("token", "", "")
	p.HTTPClient.Transport = &cfRoundTripper{handler: handler}

	// Present with wildcard
	err := p.Present("*.wildcard.org", "token123", "token123.auth")
	if err != nil {
		t.Fatalf("Present for wildcard failed: %v", err)
	}

	if createdRecordName != "_acme-challenge.wildcard.org" {
		t.Errorf("expected TXT record name '_acme-challenge.wildcard.org', got %q", createdRecordName)
	}
}
