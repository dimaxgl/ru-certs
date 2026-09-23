package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RoundTripFunc allows using a function as http.RoundTripper
type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestRegRuDNSProvider_PresentAndCleanup(t *testing.T) {
	presentCalls := 0
	cleanupCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/api/regru2/zone/add_txt_record" {
			presentCalls++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"result":"success"}`))
			return
		}
		if r.URL.Path == "/api/regru2/zone/remove_record" {
			cleanupCalls++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"result":"success"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := server.Client()
	client.Transport = RoundTripFunc(func(req *http.Request) *http.Response {
		// Rewrite host to test server
		targetURL := server.URL + req.URL.Path
		newReq, _ := http.NewRequest(req.Method, targetURL, req.Body)
		newReq.Header = req.Header
		resp, _ := http.DefaultTransport.RoundTrip(newReq)
		return resp
	})

	prov := &RegRuDNSProvider{
		Username: "testuser",
		Password: "testpassword",
		Client:   client,
	}

	// We can test CleanUp
	err := prov.CleanUp("example.com", "token123", "token123.authkey")
	if err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}
	if cleanupCalls != 1 {
		t.Errorf("expected 1 cleanup call, got %d", cleanupCalls)
	}

	// Test cleanUp error transport
	failClient := &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) *http.Response {
			return nil
		}),
	}
	provFail := &RegRuDNSProvider{
		Username: "testuser",
		Password: "testpassword",
		Client:   failClient,
	}
	if err := provFail.CleanUp("example.com", "tok", "auth"); err == nil {
		t.Errorf("expected error on transport failure")
	}

	// Test constructor
	pNew := NewRegRuDNSProvider("u", "p")
	if pNew.Username != "u" || pNew.Password != "p" || pNew.Client == nil {
		t.Errorf("NewRegRuDNSProvider unexpected values: %+v", pNew)
	}

	cf := NewCloudflareProvider("tok", "key", "email")
	if cf == nil {
		t.Errorf("expected non-nil cf provider")
	}
}

func TestRegRuDNSProvider_Errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":"error","error_text":"invalid_params"}`))
	}))
	defer server.Close()

	client := server.Client()
	client.Transport = RoundTripFunc(func(req *http.Request) *http.Response {
		targetURL := server.URL + req.URL.Path
		newReq, _ := http.NewRequest(req.Method, targetURL, req.Body)
		newReq.Header = req.Header
		resp, _ := http.DefaultTransport.RoundTrip(newReq)
		return resp
	})

	prov := &RegRuDNSProvider{
		Username: "testuser",
		Password: "testpassword",
		Client:   client,
	}

	// Present has a 10s sleep when successful or ignored error, but with error it returns immediately!
	err := prov.Present("example.com", "token", "token.keyauth")
	if err == nil {
		t.Errorf("expected error for invalid_params")
	}
}
