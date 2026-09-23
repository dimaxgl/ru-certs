package configgen

import (
	"bytes"
	"fmt"
	"path/filepath"
	"text/template"
)

const traefikTemplate = `# Auto-generated multi-certificate dynamic configuration for {{ .Domain }} by ru-certs
# Traefik automatically selects the best matching certificate by SNI and client cipher support.

tls:
  certificates:
{{- if .HasLetsEncrypt }}
    - certFile: {{ .LetsEncryptCert }}
      keyFile: {{ .LetsEncryptKey }}
      stores:
        - default
{{- end }}
{{- if .HasMinTsifryRSA }}
    - certFile: {{ .MinTsifryRSACert }}
      keyFile: {{ .MinTsifryRSAKey }}
      stores:
        - default
{{- end }}
{{- if .HasGOST }}
    - certFile: {{ .GOSTCert }}
      keyFile: {{ .GOSTKey }}
      stores:
        - default
{{- end }}

  stores:
    default:
      defaultCertificate:
{{- if .HasLetsEncrypt }}
        certFile: {{ .LetsEncryptCert }}
        keyFile: {{ .LetsEncryptKey }}
{{- else if .HasMinTsifryRSA }}
        certFile: {{ .MinTsifryRSACert }}
        keyFile: {{ .MinTsifryRSAKey }}
{{- end }}
`

// GenerateTraefikConfig generates Traefik YAML dynamic TLS configuration
func GenerateTraefikConfig(basePath, domain string, hasLetsEncrypt, hasMinTsifryRSA, hasGOST bool) (string, error) {
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

	tmpl, err := template.New("traefik").Parse(traefikTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
