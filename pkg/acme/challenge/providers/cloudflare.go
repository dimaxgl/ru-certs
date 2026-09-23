package providers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudflareProvider implements ACME DNS-01 challenge via Cloudflare API v4
type CloudflareProvider struct {
	APIToken   string
	APIKey     string
	APIEmail   string
	HTTPClient *http.Client
	recordIDs  map[string]string // domain -> recordID
	mu         sync.Mutex
}

func NewCloudflareProvider(apiToken, apiKey, apiEmail string) *CloudflareProvider {
	return &CloudflareProvider{
		APIToken:   apiToken,
		APIKey:     apiKey,
		APIEmail:   apiEmail,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		recordIDs:  make(map[string]string),
	}
}

func (c *CloudflareProvider) newRequest(method, url string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	} else if c.APIKey != "" && c.APIEmail != "" {
		req.Header.Set("X-Auth-Key", c.APIKey)
		req.Header.Set("X-Auth-Email", c.APIEmail)
	} else {
		return nil, fmt.Errorf("either Cloudflare API token or API key + email must be provided")
	}

	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *CloudflareProvider) findZoneID(domain string) (string, error) {
	// Strip wildcard
	domain = strings.TrimPrefix(domain, "*.")
	parts := strings.Split(domain, ".")

	for i := 0; i < len(parts)-1; i++ {
		zoneCandidate := strings.Join(parts[i:], ".")
		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s&status=active", zoneCandidate)
		req, err := c.newRequest("GET", url, nil)
		if err != nil {
			return "", err
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return "", err
		}

		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}

		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if decodeErr == nil && result.Success && len(result.Result) > 0 {
			return result.Result[0].ID, nil
		}
	}

	return "", fmt.Errorf("cloudflare zone not found for domain %s", domain)
}

func (c *CloudflareProvider) Present(domain, token, keyAuth string) error {
	zoneID, err := c.findZoneID(domain)
	if err != nil {
		return err
	}

	h := sha256.Sum256([]byte(keyAuth))
	txtValue := base64.RawURLEncoding.EncodeToString(h[:])
	recordName := "_acme-challenge." + strings.TrimPrefix(domain, "*.")

	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    recordName,
		"content": txtValue,
		"ttl":     120,
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	req, err := c.newRequest("POST", url, payload)
	if err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode cloudflare response: %w", err)
	}

	if !result.Success {
		var errMsgs []string
		for _, e := range result.Errors {
			errMsgs = append(errMsgs, e.Message)
		}
		return fmt.Errorf("cloudflare error: %s", strings.Join(errMsgs, ", "))
	}

	c.mu.Lock()
	key := fmt.Sprintf("%s:%s", recordName, token)
	c.recordIDs[key] = result.Result.ID
	c.mu.Unlock()

	return nil
}

func (c *CloudflareProvider) CleanUp(domain, token, keyAuth string) error {
	recordName := "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	key := fmt.Sprintf("%s:%s", recordName, token)

	c.mu.Lock()
	recordID, ok := c.recordIDs[key]
	delete(c.recordIDs, key)
	c.mu.Unlock()

	if !ok || recordID == "" {
		return nil
	}

	zoneID, err := c.findZoneID(domain)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	req, err := c.newRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
