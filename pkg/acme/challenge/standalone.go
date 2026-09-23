package challenge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// StandaloneProvider runs a lightweight HTTP server on port 80 to fulfill HTTP-01 challenges
type StandaloneProvider struct {
	Port   int
	server *http.Server
	tokens map[string]string
	mu     sync.RWMutex
}

func NewStandaloneProvider(port int) *StandaloneProvider {
	if port == 0 {
		port = 80
	}
	return &StandaloneProvider{
		Port:   port,
		tokens: make(map[string]string),
	}
}

func (s *StandaloneProvider) Present(domain, token, keyAuth string) error {
	s.mu.Lock()
	s.tokens[token] = keyAuth
	s.mu.Unlock()

	if s.server != nil {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.URL.Path[len("/.well-known/acme-challenge/"):]
		s.mu.RLock()
		auth, exists := s.tokens[reqToken]
		s.mu.RUnlock()

		if exists {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(auth))
		} else {
			http.NotFound(w, r)
		}
	})

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("failed to bind standalone port %d: %w", s.Port, err)
	}

	s.server = &http.Server{Handler: mux}
	go func() {
		_ = s.server.Serve(listener)
	}()

	return nil
}

func (s *StandaloneProvider) CleanUp(domain, token, keyAuth string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	shouldClose := len(s.tokens) == 0 && s.server != nil
	server := s.server
	if shouldClose {
		s.server = nil
	}
	s.mu.Unlock()

	if shouldClose && server != nil {
		return server.Shutdown(context.Background())
	}
	return nil
}
