package challenge

import "github.com/dimaxgl/ru-certs/pkg/acme/challenge/providers"

func NewCloudflareProvider(apiToken, apiKey, apiEmail string) Provider {
	return providers.NewCloudflareProvider(apiToken, apiKey, apiEmail)
}
