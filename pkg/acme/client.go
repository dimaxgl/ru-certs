package acme

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dimaxgl/ru-certs/pkg/ca"
)

// Directory contains RFC 8555 ACME endpoints
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// Account represents ACME Account
type Account struct {
	URI     string   `json:"uri,omitempty"`
	Status  string   `json:"status,omitempty"`
	Orders  string   `json:"orders,omitempty"`
	Contact []string `json:"contact,omitempty"`
}

// Order represents ACME Order
type Order struct {
	URI            string       `json:"uri,omitempty"`
	Status         string       `json:"status,omitempty"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Authorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Expires    string      `json:"expires"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
	Error  any    `json:"error,omitempty"`
}

// Client manages RFC 8555 interaction
type Client struct {
	DirectoryURL string
	Directory    *Directory
	Signer       crypto.Signer
	AccountURL   string
	HTTPClient   *http.Client
}

// NewClient initializes ACME client and fetches directory
func NewClient(dirURL string, signer crypto.Signer) (*Client, error) {
	rootPool, err := x509.SystemCertPool()
	if err != nil || rootPool == nil {
		rootPool = x509.NewCertPool()
	}
	rootPool.AppendCertsFromPEM(ca.GetMergedBundle())

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootPool,
		},
	}

	c := &Client{
		DirectoryURL: dirURL,
		Signer:       signer,
		HTTPClient: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
	}

	resp, err := c.HTTPClient.Get(dirURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ACME directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory returned status: %d", resp.StatusCode)
	}

	var dir Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("failed to decode directory JSON: %w", err)
	}
	c.Directory = &dir
	return c, nil
}

// GetNonce requests a fresh Replay-Nonce
func (c *Client) GetNonce() (string, error) {
	resp, err := c.HTTPClient.Head(c.Directory.NewNonce)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %w", err)
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("missing Replay-Nonce header")
	}
	return nonce, nil
}

// PostJWS sends a signed JWS POST request with automatic badNonce retry
func (c *Client) PostJWS(targetURL string, payload any, kid string) (*http.Response, []byte, error) {
	return c.postJWSRetry(targetURL, payload, kid, 2)
}

func (c *Client) postJWSRetry(targetURL string, payload any, kid string, retriesLeft int) (*http.Response, []byte, error) {
	nonce, err := c.GetNonce()
	if err != nil {
		return nil, nil, err
	}

	var payloadBytes []byte
	if payload != nil {
		if pb, ok := payload.([]byte); ok {
			payloadBytes = pb
		} else {
			payloadBytes, err = json.Marshal(payload)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	signedBody, err := SignJWS(c.Signer, kid, targetURL, nonce, payloadBytes)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(string(signedBody)))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// Handle badNonce retry per RFC 8555 Section 6.5
	if resp.StatusCode == http.StatusBadRequest && retriesLeft > 0 {
		var acmeErr struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(body, &acmeErr); err == nil {
			if strings.HasSuffix(acmeErr.Type, ":badNonce") || strings.Contains(acmeErr.Detail, "nonce") {
				return c.postJWSRetry(targetURL, payload, kid, retriesLeft-1)
			}
		}
	}

	return resp, body, nil
}

// RegisterAccount creates or recovers an ACME account
func (c *Client) RegisterAccount(email string) (*Account, error) {
	reqPayload := map[string]any{
		"termsOfServiceAgreed": true,
	}
	if email != "" {
		reqPayload["contact"] = []string{fmt.Sprintf("mailto:%s", email)}
	}

	resp, body, err := c.PostJWS(c.Directory.NewAccount, reqPayload, "")
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("account registration failed (status %d): %s", resp.StatusCode, string(body))
	}

	accURL := resp.Header.Get("Location")
	if accURL != "" {
		c.AccountURL = accURL
	}

	var acc Account
	if err := json.Unmarshal(body, &acc); err != nil {
		return nil, err
	}
	acc.URI = c.AccountURL
	return &acc, nil
}

// CreateOrder places a new certificate order for domains
func (c *Client) CreateOrder(domains []string) (*Order, error) {
	var idents []Identifier
	for _, d := range domains {
		idents = append(idents, Identifier{Type: "dns", Value: d})
	}

	reqPayload := map[string]any{
		"identifiers": idents,
	}

	resp, body, err := c.PostJWS(c.Directory.NewOrder, reqPayload, c.AccountURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create order failed (status %d): %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, err
	}
	order.URI = resp.Header.Get("Location")
	return &order, nil
}

// FetchOrder retrieves the current state of an order
func (c *Client) FetchOrder(orderURL string) (*Order, error) {
	resp, body, err := c.PostJWS(orderURL, nil, c.AccountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch order failed (status %d): %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, err
	}
	if order.URI == "" {
		order.URI = orderURL
	}
	return &order, nil
}

// FetchAuthorization retrieves challenge requirements for a domain
func (c *Client) FetchAuthorization(authURL string) (*Authorization, error) {
	resp, body, err := c.PostJWS(authURL, nil, c.AccountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch authorization failed (status %d): %s", resp.StatusCode, string(body))
	}

	var auth Authorization
	if err := json.Unmarshal(body, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

// TriggerChallenge tells CA to verify the challenge
func (c *Client) TriggerChallenge(challengeURL string) error {
	resp, body, err := c.PostJWS(challengeURL, map[string]any{}, c.AccountURL)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trigger challenge failed (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// FinalizeOrder submits CSR to get the certificate issued and polls until valid
func (c *Client) FinalizeOrder(finalizeURL string, orderURL string, rawCSRDER []byte) (*Order, error) {
	reqPayload := map[string]any{
		"csr": base64.RawURLEncoding.EncodeToString(rawCSRDER),
	}

	resp, body, err := c.PostJWS(finalizeURL, reqPayload, c.AccountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("finalize order failed (status %d): %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, err
	}
	if order.URI == "" {
		order.URI = orderURL
	}

	// Poll order until certificate URL is populated if status is processing/pending
	if order.Certificate == "" && order.URI != "" {
		for i := 0; i < 20; i++ {
			time.Sleep(1 * time.Second)
			polledOrder, err := c.FetchOrder(order.URI)
			if err != nil {
				continue
			}
			if polledOrder.Certificate != "" {
				return polledOrder, nil
			}
			if polledOrder.Status == "invalid" {
				return nil, fmt.Errorf("order became invalid during finalization")
			}
		}
	}

	return &order, nil
}

// DownloadCertificate downloads certificate chain from URL
func (c *Client) DownloadCertificate(certURL string) ([]byte, error) {
	resp, body, err := c.PostJWS(certURL, nil, c.AccountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download cert failed (status %d): %s", resp.StatusCode, string(body))
	}
	return body, nil
}
