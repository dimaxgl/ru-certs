package mock

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

type MockACMEServer struct {
	Server   *httptest.Server
	mu       sync.Mutex
	nonces   map[string]bool
	accounts map[string]MockAccount
	orders   map[string]*MockOrder
	authz    map[string]*MockAuthz
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
}

type MockAccount struct {
	ID      string
	Contact []string
	Key     crypto.PublicKey
	Status  string
}

type MockOrder struct {
	ID             string
	Identifiers    []map[string]string
	Status         string
	Authorizations []string
	Finalize       string
	Certificate    string
}

type MockAuthz struct {
	ID         string
	Identifier map[string]string
	Status     string
	Challenges []MockChallenge
}

type MockChallenge struct {
	Type   string
	URL    string
	Token  string
	Status string
}

func NewMockACMEServer() *MockACMEServer {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Mock Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	s := &MockACMEServer{
		nonces:   make(map[string]bool),
		accounts: make(map[string]MockAccount),
		orders:   make(map[string]*MockOrder),
		authz:    make(map[string]*MockAuthz),
		caCert:   cert,
		caKey:    key,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", s.handleDirectory)
	mux.HandleFunc("/new-nonce", s.handleNewNonce)
	mux.HandleFunc("/new-account", s.handleNewAccount)
	mux.HandleFunc("/new-order", s.handleNewOrder)
	mux.HandleFunc("/authz/", s.handleAuthz)
	mux.HandleFunc("/chall/", s.handleChallenge)
	mux.HandleFunc("/finalize/", s.handleFinalize)
	mux.HandleFunc("/cert/", s.handleCertificate)

	s.Server = httptest.NewServer(mux)
	return s
}

func (s *MockACMEServer) Close() {
	s.Server.Close()
}

func (s *MockACMEServer) URL() string {
	return s.Server.URL + "/directory"
}

func (s *MockACMEServer) issueNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := make([]byte, 16)
	rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	s.nonces[n] = true
	return n
}

func (s *MockACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   s.Server.URL + "/new-nonce",
		"newAccount": s.Server.URL + "/new-account",
		"newOrder":   s.Server.URL + "/new-order",
		"revokeCert": s.Server.URL + "/revoke-cert",
		"keyChange":  s.Server.URL + "/key-change",
	})
}

func (s *MockACMEServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.issueNonce())
	w.WriteHeader(http.StatusOK)
}

func (s *MockACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.issueNonce())
	accID := "acc-123"
	accURL := s.Server.URL + "/account/" + accID
	w.Header().Set("Location", accURL)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:admin@test.ru"},
	})
}

func (s *MockACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.issueNonce())
	orderID := fmt.Sprintf("order-%d", time.Now().UnixNano())
	authID := fmt.Sprintf("auth-%d", time.Now().UnixNano())

	s.mu.Lock()
	s.authz[authID] = &MockAuthz{
		ID: authID,
		Identifier: map[string]string{
			"type":  "dns",
			"value": "example.ru",
		},
		Status: "pending",
		Challenges: []MockChallenge{
			{
				Type:   "http-01",
				URL:    s.Server.URL + "/chall/http-" + authID,
				Token:  "tok-http-123",
				Status: "pending",
			},
			{
				Type:   "dns-01",
				URL:    s.Server.URL + "/chall/dns-" + authID,
				Token:  "tok-dns-123",
				Status: "pending",
			},
		},
	}

	order := &MockOrder{
		ID: orderID,
		Identifiers: []map[string]string{
			{"type": "dns", "value": "example.ru"},
		},
		Status:         "pending",
		Authorizations: []string{s.Server.URL + "/authz/" + authID},
		Finalize:       s.Server.URL + "/finalize/" + orderID,
		Certificate:    s.Server.URL + "/cert/" + orderID,
	}
	s.orders[orderID] = order
	s.mu.Unlock()

	orderURL := s.Server.URL + "/orders/" + orderID
	w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (s *MockACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	authID := parts[len(parts)-1]

	s.mu.Lock()
	auth, ok := s.authz[authID]
	s.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Replay-Nonce", s.issueNonce())
	json.NewEncoder(w).Encode(auth)
}

func (s *MockACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.issueNonce())

	s.mu.Lock()
	for _, auth := range s.authz {
		for i := range auth.Challenges {
			auth.Challenges[i].Status = "valid"
		}
		auth.Status = "valid"
	}
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
}

func (s *MockACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	orderID := parts[len(parts)-1]

	s.mu.Lock()
	order := s.orders[orderID]
	if order != nil {
		order.Status = "valid"
	}
	s.mu.Unlock()

	w.Header().Set("Replay-Nonce", s.issueNonce())
	json.NewEncoder(w).Encode(order)
}

func (s *MockACMEServer) handleCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
	w.Write(certPem)
}
