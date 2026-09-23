package challenge

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTP01Webroot_ProvisionAndCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "webroot-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	w := NewHTTP01Webroot(tempDir)
	token := "token-12345"
	keyAuth := "token-12345.secret-auth-key"

	cleanup, err := w.Provision(token, keyAuth)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected non-nil cleanup function")
	}

	expectedPath := filepath.Join(tempDir, ".well-known", "acme-challenge", token)
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read challenge file at %s: %v", expectedPath, err)
	}
	if string(content) != keyAuth {
		t.Errorf("expected content %q, got %q", keyAuth, string(content))
	}

	// Test cleanup function
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup returned error: %v", err)
	}

	if _, err := os.Stat(expectedPath); !os.IsNotExist(err) {
		t.Errorf("expected challenge file to be deleted")
	}
}

func TestWebrootProvider_PresentAndCleanUp(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "webroot-prov-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	w := NewWebrootProvider(tempDir)
	domain := "example.com"
	token := "tok-abc"
	keyAuth := "tok-abc.key-xyz"

	if err := w.Present(domain, token, keyAuth); err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	expectedPath := filepath.Join(tempDir, ".well-known", "acme-challenge", token)
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(content) != keyAuth {
		t.Errorf("expected %q, got %q", keyAuth, string(content))
	}

	if err := w.CleanUp(domain, token, keyAuth); err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}
	if _, err := os.Stat(expectedPath); !os.IsNotExist(err) {
		t.Errorf("file should be removed after CleanUp")
	}
}

func TestHTTP01Standalone(t *testing.T) {
	port := 18088
	s := NewHTTP01Standalone(port)

	token := "token-stand"
	keyAuth := "auth-stand"
	s.Register(token, keyAuth)

	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer s.Stop(context.Background())

	time.Sleep(50 * time.Millisecond)

	// Fetch token
	url := fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/%s", port, token)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != keyAuth {
		t.Errorf("expected body %q, got %q", keyAuth, string(body))
	}

	// Fetch unknown token -> 404
	badURL := fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/unknown", port)
	badResp, err := http.Get(badURL)
	if err != nil {
		t.Fatalf("GET bad token failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", badResp.StatusCode)
	}

	// Test default port
	sDefault := NewHTTP01Standalone(0)
	if sDefault.Port != 80 {
		t.Errorf("expected port 80 when initialized with 0, got %d", sDefault.Port)
	}
}

func TestStandaloneProvider_PresentAndCleanUp(t *testing.T) {
	port := 18089
	s := NewStandaloneProvider(port)
	if s.Port != port {
		t.Errorf("expected port %d, got %d", port, s.Port)
	}

	s0 := NewStandaloneProvider(0)
	if s0.Port != 80 {
		t.Errorf("expected default port 80, got %d", s0.Port)
	}

	domain := "example.com"
	token := "tok-123"
	keyAuth := "tok-123.auth-456"

	// 1. Present
	if err := s.Present(domain, token, keyAuth); err != nil {
		t.Fatalf("Present failed: %v", err)
	}
	// Present second token (tests server != nil branch)
	token2 := "tok-456"
	keyAuth2 := "tok-456.auth-789"
	if err := s.Present(domain, token2, keyAuth2); err != nil {
		t.Fatalf("Present second token failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Fetch token 1
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/%s", port, token))
	if err != nil {
		t.Fatalf("GET token 1 failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != keyAuth {
		t.Errorf("expected %q, got %q", keyAuth, string(body))
	}

	// Fetch missing token
	resp404, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/none", port))
	if err != nil {
		t.Fatalf("GET none failed: %v", err)
	}
	resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp404.StatusCode)
	}

	// CleanUp token 2 (server stays up because token 1 still exists)
	if err := s.CleanUp(domain, token2, keyAuth2); err != nil {
		t.Fatalf("CleanUp token2 failed: %v", err)
	}

	// CleanUp token 1 (should shut down server)
	if err := s.CleanUp(domain, token, keyAuth); err != nil {
		t.Fatalf("CleanUp token1 failed: %v", err)
	}

	// Subsequent cleanup when server is nil
	if err := s.CleanUp(domain, token, keyAuth); err != nil {
		t.Fatalf("subsequent CleanUp failed: %v", err)
	}
}

func TestStandaloneProvider_BindFailure(t *testing.T) {
	// Bind a port first on all interfaces (:port)
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	s := NewStandaloneProvider(port)
	err = s.Present("example.com", "tok", "auth")
	if err == nil {
		t.Errorf("expected error when binding to already occupied port %d", port)
	}
}
