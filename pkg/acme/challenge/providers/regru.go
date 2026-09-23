package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RegRuDNSProvider implements DNS-01 challenge via Reg.ru API v2
type RegRuDNSProvider struct {
	Username string
	Password string
	Client   *http.Client
}

func NewRegRuDNSProvider(user, pass string) *RegRuDNSProvider {
	return &RegRuDNSProvider{
		Username: user,
		Password: pass,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AddTXTRecord adds _acme-challenge TXT record via reg.ru API
func (p *RegRuDNSProvider) AddTXTRecord(domain, subdomain, value string) error {
	reqData := map[string]any{
		"username":        p.Username,
		"password":        p.Password,
		"domains":         []map[string]string{{"dname": domain}},
		"subdomain":       subdomain,
		"text":            value,
		"output_format":   "json",
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	resp, err := p.Client.Post("https://api.reg.ru/api/regru2/zone/add_txt_record", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("reg.ru API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reg.ru returned %d: %s", resp.StatusCode, string(respBody))
	}

	var respData struct {
		Result    string `json:"result"`
		ErrorCode string `json:"error_code"`
		ErrorText string `json:"error_text"`
	}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if respData.Result == "error" || respData.ErrorCode != "" {
			return fmt.Errorf("reg.ru API error [%s]: %s", respData.ErrorCode, respData.ErrorText)
		}
	}

	return nil
}
