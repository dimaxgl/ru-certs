package configgen

import (
	"strings"
	"testing"
)

func TestGenerateNginxConfig(t *testing.T) {
	cfg, err := GenerateNginxConfig("/etc/ru-certs", "example.ru", true, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(cfg, "/etc/ru-certs/live/example.ru/letsencrypt/fullchain.pem") {
		t.Errorf("missing letsencrypt cert path")
	}
	if !strings.Contains(cfg, "/etc/ru-certs/live/example.ru/mintsifry-rsa/fullchain.pem") {
		t.Errorf("missing mintsifry cert path")
	}
	if !strings.Contains(cfg, "server_name example.ru") {
		t.Errorf("missing server_name")
	}
}

func TestGenerateTraefikConfig(t *testing.T) {
	cfg, err := GenerateTraefikConfig("/etc/ru-certs", "example.ru", true, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(cfg, "certFile: /etc/ru-certs/live/example.ru/letsencrypt/fullchain.pem") {
		t.Errorf("missing letsencrypt cert in traefik")
	}
	if !strings.Contains(cfg, "certFile: /etc/ru-certs/live/example.ru/mintsifry-rsa/fullchain.pem") {
		t.Errorf("missing mintsifry cert in traefik")
	}
}
