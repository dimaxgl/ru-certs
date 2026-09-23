package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RegRuDNSProvider automates DNS-01 TXT record management via Reg.ru API v2
type RegRuDNSProvider struct {
	Username string
	Password string
	Client   *http.Client
}

func NewRegRuDNSProvider(username, password string) *RegRuDNSProvider {
	return &RegRuDNSProvider{
		Username: username,
		Password: password,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *RegRuDNSProvider) Present(domain, token, keyAuth string) error {
	h := sha256.Sum256([]byte(keyAuth))
	txtVal := base64.RawURLEncoding.EncodeToString(h[:])
	subdomain := "_acme-challenge"

	params := url.Values{}
	params.Set("username", r.Username)
	params.Set("password", r.Password)
	params.Set("output_format", "json")
	params.Set("dname", domain)
	params.Set("subdomain", subdomain)
	params.Set("text", txtVal)

	resp, err := r.Client.PostForm("https://api.reg.ru/api/regru2/zone/add_txt_record", params)
	if err != nil {
		return fmt.Errorf("reg.ru api error: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
		Error  string `json:"error_text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Result != "success" && !strings.Contains(result.Error, "already exists") {
		return fmt.Errorf("reg.ru failed to add TXT record: %s", result.Error)
	}

	time.Sleep(10 * time.Second)
	return nil
}

func (r *RegRuDNSProvider) CleanUp(domain, token, keyAuth string) error {
	h := sha256.Sum256([]byte(keyAuth))
	txtVal := base64.RawURLEncoding.EncodeToString(h[:])
	subdomain := "_acme-challenge"

	params := url.Values{}
	params.Set("username", r.Username)
	params.Set("password", r.Password)
	params.Set("output_format", "json")
	params.Set("dname", domain)
	params.Set("subdomain", subdomain)
	params.Set("text", txtVal)

	resp, err := r.Client.PostForm("https://api.reg.ru/api/regru2/zone/remove_record", params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
