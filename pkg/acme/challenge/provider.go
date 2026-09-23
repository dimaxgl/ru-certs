package challenge

// Provider defines the interface for ACME challenge provisioning
type Provider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}
