package configgen

import (
	"bytes"
	"fmt"
	"path/filepath"
	"text/template"
)

type MultiCertPaths struct {
	Domain            string
	MinTsifryRSACert  string
	MinTsifryRSAKey   string
	LetsEncryptCert   string
	LetsEncryptKey    string
	GOSTCert          string
	GOSTKey           string
	HasMinTsifryRSA   bool
	HasLetsEncrypt    bool
	HasGOST           bool
}

const nginxTemplate = `# Auto-generated multi-certificate configuration for {{ .Domain }} by ru-certs
# This configuration leverages Nginx multi-certificate dual/triple handshake capability.
# Nginx dynamically selects the matching certificate (ECDSA, RSA, GOST) based on the client's supported ciphers.

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {{ .Domain }}{{ if ne .Domain "localhost" }} www.{{ .Domain }}{{ end }};

{{- if .HasLetsEncrypt }}
    # 1. Let's Encrypt / Public CA (ECDSA / RSA) - for international & standard browsers
    ssl_certificate     {{ .LetsEncryptCert }};
    ssl_certificate_key {{ .LetsEncryptKey }};
{{- end }}

{{- if .HasMinTsifryRSA }}
    # 2. Russian National CA (Минцифры / NUC Voskhod RSA) - for Russian browsers (Yandex Browser, Atom)
    ssl_certificate     {{ .MinTsifryRSACert }};
    ssl_certificate_key {{ .MinTsifryRSAKey }};
{{- end }}

{{- if .HasGOST }}
    # 3. Russian National CA (GOST R 34.10-2012) - requires Nginx compiled with OpenSSL GOST Engine
    # ssl_certificate     {{ .GOSTCert }};
    # ssl_certificate_key {{ .GOSTKey }};
{{- end }}

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    location / {
        # Proxy or root configuration
        # proxy_pass http://127.0.0.1:8080;
        root /var/www/{{ .Domain }};
        index index.html;
    }
}
`

// GenerateNginxConfig generates an Nginx server block configured for multi-certificate negotiation
func GenerateNginxConfig(basePath, domain string, hasLetsEncrypt, hasMinTsifryRSA, hasGOST bool) (string, error) {
	liveDir := filepath.Join(basePath, "live", domain)

	data := MultiCertPaths{
		Domain:           domain,
		HasLetsEncrypt:   hasLetsEncrypt,
		HasMinTsifryRSA:  hasMinTsifryRSA,
		HasGOST:          hasGOST,
		LetsEncryptCert:  filepath.Join(liveDir, "letsencrypt", "fullchain.pem"),
		LetsEncryptKey:   filepath.Join(liveDir, "letsencrypt", "privkey.pem"),
		MinTsifryRSACert: filepath.Join(liveDir, "mintsifry-rsa", "fullchain.pem"),
		MinTsifryRSAKey:  filepath.Join(liveDir, "mintsifry-rsa", "privkey.pem"),
		GOSTCert:         filepath.Join(liveDir, "gost", "fullchain.pem"),
		GOSTKey:          filepath.Join(liveDir, "gost", "privkey.pem"),
	}

	tmpl, err := template.New("nginx").Parse(nginxTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
