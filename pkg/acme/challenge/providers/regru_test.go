package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type regRuRoundTripper struct {
	handler http.HandlerFunc
}

func (rt *regRuRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.handler(rec, req)
	return rec.Result(), nil
}

func TestRegRuDNSProvider_AddTXTRecord_Success(t *testing.T) {
	var capturedBody map[string]any

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/regru2/zone/add_txt_record" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"success"}`))
	}

	p := NewRegRuDNSProvider("test-user", "test-pass")
	p.Client.Transport = &regRuRoundTripper{handler: handler}

	err := p.AddTXTRecord("example.com", "_acme-challenge", "test-token-value")
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}

	if capturedBody["username"] != "test-user" || capturedBody["password"] != "test-pass" {
		t.Errorf("expected user credentials in payload, got: %+v", capturedBody)
	}
	if capturedBody["subdomain"] != "_acme-challenge" || capturedBody["text"] != "test-token-value" {
		t.Errorf("unexpected record payload: %+v", capturedBody)
	}
}

func TestRegRuDNSProvider_AddTXTRecord_HTTPError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("502 Bad Gateway"))
	}

	p := NewRegRuDNSProvider("test-user", "test-pass")
	p.Client.Transport = &regRuRoundTripper{handler: handler}

	err := p.AddTXTRecord("example.com", "_acme-challenge", "val")
	if err == nil {
		t.Fatal("expected error on 502 status, got nil")
	}
	if !contains(err.Error(), "502") {
		t.Errorf("expected error message to contain 502, got: %v", err)
	}
}

func TestRegRuDNSProvider_AddTXTRecord_JSONErrorResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		expectErr bool
	}{
		{
			name:      "explicit error result",
			response:  `{"result":"error","error_code":"ZONE_NOT_FOUND","error_text":"Zone example.com not found"}`,
			expectErr: true,
		},
		{
			name:      "error code present without error result",
			response:  `{"result":"failed","error_code":"AUTH_FAILED","error_text":"Invalid username or password"}`,
			expectErr: true,
		},
		{
			name:      "success response",
			response:  `{"result":"success"}`,
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tc.response))
			}

			p := NewRegRuDNSProvider("u", "p")
			p.Client.Transport = &regRuRoundTripper{handler: handler}

			err := p.AddTXTRecord("example.com", "_acme-challenge", "val")
			if tc.expectErr && err == nil {
				t.Errorf("expected error for response %s, got nil", tc.response)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && s != "" && (s[:len(substr)] == substr || (len(s) > len(substr) && contains(s[1:], substr)))))
}
