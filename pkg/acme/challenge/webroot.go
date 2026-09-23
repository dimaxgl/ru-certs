package challenge

import (
	"fmt"
	"os"
	"path/filepath"
)

// WebrootProvider implements HTTP-01 using a local filesystem webroot
type WebrootProvider struct {
	WebrootDir string
}

func NewWebrootProvider(webrootDir string) *WebrootProvider {
	return &WebrootProvider{WebrootDir: webrootDir}
}

func (w *WebrootProvider) Present(domain, token, keyAuth string) error {
	dir := filepath.Join(w.WebrootDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create challenge dir: %w", err)
	}

	targetFile := filepath.Join(dir, token)
	return os.WriteFile(targetFile, []byte(keyAuth), 0644)
}

func (w *WebrootProvider) CleanUp(domain, token, keyAuth string) error {
	targetFile := filepath.Join(w.WebrootDir, ".well-known", "acme-challenge", token)
	_ = os.Remove(targetFile)
	return nil
}
