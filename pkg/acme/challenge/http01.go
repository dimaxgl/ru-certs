package challenge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// HTTP01Webroot handles .well-known/acme-challenge/ writing
type HTTP01Webroot struct {
	WebrootDir string
}

func NewHTTP01Webroot(dir string) *HTTP01Webroot {
	return &HTTP01Webroot{WebrootDir: dir}
}

func (w *HTTP01Webroot) Provision(token string, keyAuth string) (func() error, error) {
	targetDir := filepath.Join(w.WebrootDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create challenge dir: %w", err)
	}

	targetFile := filepath.Join(targetDir, token)
	if err := os.WriteFile(targetFile, []byte(keyAuth), 0644); err != nil {
		return nil, fmt.Errorf("failed to write challenge file: %w", err)
	}

	cleanup := func() error {
		return os.Remove(targetFile)
	}

	return cleanup, nil
}

// HTTP01Standalone starts a local HTTP server on port 80 (or custom port)
type HTTP01Standalone struct {
	Port   int
	server *http.Server
	tokens map[string]string
	mu     sync.RWMutex
}

func NewHTTP01Standalone(port int) *HTTP01Standalone {
	if port == 0 {
		port = 80
	}
	return &HTTP01Standalone{
		Port:   port,
		tokens: make(map[string]string),
	}
}

func (s *HTTP01Standalone) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := filepath.Base(r.URL.Path)
		s.mu.RLock()
		keyAuth, ok := s.tokens[token]
		s.mu.RUnlock()

		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(keyAuth))
	})

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("cannot bind port %d: %w", s.Port, err)
	}

	s.server = &http.Server{Handler: mux}
	go s.server.Serve(listener)
	return nil
}

func (s *HTTP01Standalone) Register(token, keyAuth string) {
	s.mu.Lock()
	s.tokens[token] = keyAuth
	s.mu.Unlock()
}

func (s *HTTP01Standalone) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
