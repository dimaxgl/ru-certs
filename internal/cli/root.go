package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dimaxgl/ru-certs/pkg/acme"
	"github.com/dimaxgl/ru-certs/pkg/acme/challenge"
	"github.com/dimaxgl/ru-certs/pkg/ca"
	"github.com/dimaxgl/ru-certs/pkg/csr"
	"github.com/dimaxgl/ru-certs/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	cfgDir         string
	acmeDirURL     string
	email          string
	domains        []string
	webrootDir     string
	standalone     bool
	standalonePort int
	dnsProvider    string
	regruUser      string
	regruPass      string
	cfToken        string
	cfKey          string
	cfEmail        string
	keyType        string
	dryRun         bool
	forceRenew     bool
	multiCert      bool
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ru-certs",
		Short: "ru-certs is an ACME client & Russian CA (Минцифры / NUC Voskhod) certificate management tool",
		Long: `ru-certs manages certificates issued by the Russian National Certification Authority (Минцифры / NUC Voskhod).
Supports automatic domain validation (HTTP-01, DNS-01 via Reg.ru), regulatory CSR generation with ASN.1 OIDs (INN, OGRN, SNILS),
and root CA trust store installation.`,
	}

	rootCmd.PersistentFlags().StringVar(&cfgDir, "config-dir", "/etc/ru-certs", "Directory for configuration and certificate storage")
	rootCmd.PersistentFlags().StringVar(&acmeDirURL, "server", acme.NucAcmeProductionDirectory, "ACME Directory URL")
	rootCmd.PersistentFlags().StringVarP(&email, "email", "m", "", "Email address for ACME registration and notifications")

	rootCmd.AddCommand(newCertCmd())
	rootCmd.AddCommand(newCSRCmd())
	rootCmd.AddCommand(newCACmd())
	rootCmd.AddCommand(newRenewCmd())
	rootCmd.AddCommand(newConfigCmd())

	return rootCmd
}

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Obtain and manage SSL/TLS certificates via ACME",
	}

	obtainCmd := &cobra.Command{
		Use:   "obtain",
		Short: "Request and obtain a new certificate via ACME",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(domains) == 0 {
				return fmt.Errorf("at least one domain must be specified using -d / --domain")
			}
			if email == "" {
				return fmt.Errorf("email must be specified using -m / --email")
			}

			store := storage.NewStorage(cfgDir)
			accKey, err := store.LoadOrGenerateAccountKey(email)
			if err != nil {
				return fmt.Errorf("failed to get account key: %w", err)
			}

			client, err := acme.NewClient(acmeDirURL, accKey)
			if err != nil {
				return fmt.Errorf("failed to init ACME client: %w", err)
			}

			fmt.Printf("Registering / verifying account %s...\n", email)
			acc, err := client.RegisterAccount(email)
			if err != nil {
				return fmt.Errorf("account registration failed: %w", err)
			}
			fmt.Printf("Account active at: %s\n", acc.URI)

			var chalProvider challenge.Provider
			chalType := "http-01"
			if standalone {
				chalProvider = challenge.NewStandaloneProvider(standalonePort)
			} else if webrootDir != "" {
				chalProvider = challenge.NewWebrootProvider(webrootDir)
			} else if dnsProvider == "regru" {
				chalType = "dns-01"
				chalProvider = challenge.NewRegRuDNSProvider(regruUser, regruPass)
			} else if dnsProvider == "cloudflare" || dnsProvider == "cf" {
				chalType = "dns-01"
				token := cfToken
				if token == "" {
					token = os.Getenv("CLOUDFLARE_API_TOKEN")
				}
				key := cfKey
				if key == "" {
					key = os.Getenv("CLOUDFLARE_API_KEY")
				}
				cfEmailAddr := cfEmail
				if cfEmailAddr == "" {
					cfEmailAddr = os.Getenv("CLOUDFLARE_EMAIL")
				}
				chalProvider = challenge.NewCloudflareProvider(token, key, cfEmailAddr)
			} else {
				return fmt.Errorf("a challenge method must be specified (--standalone, --webroot, or --dns regru/cloudflare)")
			}

			fmt.Printf("Requesting certificate for %s...\n", strings.Join(domains, ", "))
			order, err := client.CreateOrder(domains)
			if err != nil {
				return fmt.Errorf("new order failed: %w", err)
			}

			// Process authorizations
			for _, authURL := range order.Authorizations {
				auth, err := client.FetchAuthorization(authURL)
				if err != nil {
					return fmt.Errorf("failed to fetch auth: %w", err)
				}
				if auth.Status == "valid" {
					continue
				}

				var targetChal *acme.Challenge
				for _, ch := range auth.Challenges {
					if ch.Type == chalType {
						targetChal = &ch
						break
					}
				}
				if targetChal == nil {
					return fmt.Errorf("challenge %s not offered for identifier %s", chalType, auth.Identifier.Value)
				}

				keyAuth, err := acme.KeyAuthorization(targetChal.Token, accKey)
				if err != nil {
					return err
				}

				if err := chalProvider.Present(auth.Identifier.Value, targetChal.Token, keyAuth); err != nil {
					return fmt.Errorf("challenge present failed: %w", err)
				}
				defer chalProvider.CleanUp(auth.Identifier.Value, targetChal.Token, keyAuth)

				if err := client.TriggerChallenge(targetChal.URL); err != nil {
					return fmt.Errorf("answer challenge failed: %w", err)
				}

				// Wait for auth to become valid
				fmt.Printf("Waiting for authorization verification of %s...\n", auth.Identifier.Value)
				authValid := false
				for i := 0; i < 30; i++ {
					time.Sleep(2 * time.Second)
					auth, err = client.FetchAuthorization(authURL)
					if err != nil {
						return err
					}
					if auth.Status == "valid" {
						authValid = true
						break
					}
					if auth.Status == "invalid" {
						return fmt.Errorf("authorization for %s failed (status: invalid)", auth.Identifier.Value)
					}
				}
				if !authValid {
					return fmt.Errorf("authorization timeout for %s (current status: %s)", auth.Identifier.Value, auth.Status)
				}
			}

			// Generate CSR & Key
			csrRes, err := csr.BuildCSR(&csr.CSRConfig{
				Profile:    csr.ProfileDV,
				CommonName: domains[0],
				SANs:       domains[1:],
				KeyType:    keyType,
			})
			if err != nil {
				return fmt.Errorf("failed to generate CSR: %w", err)
			}

			fmt.Println("Finalizing order with CSR...")
			finalOrder, err := client.FinalizeOrder(order.Finalize, order.URI, csrRes.CSRDER)
			if err != nil {
				return fmt.Errorf("finalize order failed: %w", err)
			}

			fmt.Println("Downloading issued certificate...")
			certBundle, err := client.DownloadCertificate(finalOrder.Certificate)
			if err != nil {
				return fmt.Errorf("download certificate failed: %w", err)
			}

			renewCfg := storage.RenewalConfig{
				Domain:        domains[0],
				SANs:          domains[1:],
				ChallengeType: chalType,
				WebrootDir:    webrootDir,
				KeyType:       keyType,
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
			}

			if err := store.SaveCertificates(domains[0], certBundle, csrRes.PrivateKeyPEM, renewCfg); err != nil {
				return fmt.Errorf("failed to save certificates: %w", err)
			}

			fmt.Printf("Certificate successfully obtained and saved to %s\n", store.LiveDir(domains[0]))
			return nil
		},
	}

	obtainCmd.Flags().StringSliceVarP(&domains, "domain", "d", nil, "Domain names to include in the certificate")
	obtainCmd.Flags().StringVar(&webrootDir, "webroot", "", "Path to webroot directory for HTTP-01 challenge")
	obtainCmd.Flags().BoolVar(&standalone, "standalone", false, "Use built-in standalone web server for HTTP-01")
	obtainCmd.Flags().IntVar(&standalonePort, "standalone-port", 80, "Port for standalone server")
	obtainCmd.Flags().StringVar(&dnsProvider, "dns", "", "DNS challenge provider (regru, cloudflare)")
	obtainCmd.Flags().StringVar(&regruUser, "regru-user", "", "Reg.ru API username")
	obtainCmd.Flags().StringVar(&regruPass, "regru-password", "", "Reg.ru API password")
	obtainCmd.Flags().StringVar(&cfToken, "cf-token", "", "Cloudflare API Token (or CLOUDFLARE_API_TOKEN env)")
	obtainCmd.Flags().StringVar(&cfKey, "cf-key", "", "Cloudflare Global API Key (or CLOUDFLARE_API_KEY env)")
	obtainCmd.Flags().StringVar(&cfEmail, "cf-email", "", "Cloudflare Account Email (or CLOUDFLARE_EMAIL env)")
	obtainCmd.Flags().StringVar(&keyType, "key-type", "rsa2048", "Private key algorithm (rsa2048, rsa4096, ecdsa-p256)")
	obtainCmd.Flags().BoolVar(&multiCert, "multi-cert", false, "Issue dual/triple certificate bundle (Минцифры RSA + Let's Encrypt + GOST)")

	cmd.AddCommand(obtainCmd)
	return cmd
}

func newCSRCmd() *cobra.Command {
	var (
		cn, org, country, state, loc, street     string
		inn, innLE, ogrn, ogrnip, snils, email   string
		surname, givenName, title                string
		skziClass, signTool                      string
		clientProfile                            string
		keyType                                  string
		outFile                                  string
	)

	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Generate regulatory PKCS#10 Certificate Signing Requests with Russian OIDs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := &csr.CSRConfig{
				Profile:         csr.ProfileType(strings.ToLower(clientProfile)),
				CommonName:      cn,
				SANs:            domains,
				KeyType:         keyType,
				Organization:    org,
				INN:             inn,
				INNLE:           innLE,
				OGRN:            ogrn,
				OGRNIP:          ogrnip,
				SNILS:           snils,
				Surname:         surname,
				GivenName:       givenName,
				Title:           title,
				State:           state,
				Locality:        loc,
				Street:          street,
				Email:           email,
				SKZIClass:       csr.SKZIClass(skziClass),
				SubjectSignTool: signTool,
			}

			res, err := csr.BuildCSR(cfg)
			if err != nil {
				return fmt.Errorf("failed to build CSR: %w", err)
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, res.CSRPEM, 0644); err != nil {
					return err
				}
				keyFile := outFile + ".key"
				if err := os.WriteFile(keyFile, res.PrivateKeyPEM, 0600); err != nil {
					return err
				}
				fmt.Printf("CSR written to %s and private key to %s\n", outFile, keyFile)
			} else {
				fmt.Println(string(res.CSRPEM))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&clientProfile, "profile", "dv", "Profile type: dv, ov-fl, ov-ip, ov-yl")
	cmd.Flags().StringVar(&cn, "cn", "", "Common Name / FQDN")
	cmd.Flags().StringSliceVarP(&domains, "san", "d", nil, "Subject Alternative Names")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa2048", "Key algorithm: rsa2048, rsa4096, ecdsa-p256")
	cmd.Flags().StringVar(&org, "org", "", "Organization Name")
	cmd.Flags().StringVar(&country, "country", "RU", "Country code")
	cmd.Flags().StringVar(&state, "state", "", "State / Region (e.g. 77 г. Москва)")
	cmd.Flags().StringVar(&loc, "loc", "", "City / Locality")
	cmd.Flags().StringVar(&street, "street", "", "Street address")
	cmd.Flags().StringVar(&inn, "inn", "", "INN for physical person / IP (12 digits)")
	cmd.Flags().StringVar(&innLE, "inn-le", "", "INN for legal entity (10 digits)")
	cmd.Flags().StringVar(&ogrn, "ogrn", "", "OGRN (13 digits)")
	cmd.Flags().StringVar(&ogrnip, "ogrnip", "", "OGRNIP (15 digits)")
	cmd.Flags().StringVar(&snils, "snils", "", "SNILS (11 digits)")
	cmd.Flags().StringVar(&surname, "surname", "", "Surname (SN)")
	cmd.Flags().StringVar(&givenName, "given-name", "", "Given Name & Patronymic (GN)")
	cmd.Flags().StringVar(&title, "title", "", "Position / Title (T)")
	cmd.Flags().StringVar(&skziClass, "skzi-class", "KC1", "SKZI policy class (KC1, KC2, KC3, KB1, KB2)")
	cmd.Flags().StringVar(&signTool, "sign-tool", "", "Subject Sign Tool (1.2.643.100.111)")
	cmd.Flags().StringVar(&email, "email", "", "Contact Email")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "Output file path (.csr or .p10)")

	return cmd
}

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage Russian National Certification Authority (Минцифры) root trust bundles",
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install Russian Trusted Root & Intermediate CA into OS trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := ca.InstallToSystemStore(dryRun)
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	}
	installCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print installation commands without executing")

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export Russian CA bundle to a PEM file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("output file path required")
			}
			if err := ca.ExportToFile(args[0], true); err != nil {
				return err
			}
			fmt.Printf("Root CA bundle exported to %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(installCmd)
	cmd.AddCommand(exportCmd)
	return cmd
}

func newRenewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew all active certificates due for expiration",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := storage.NewStorage(cfgDir)
			configs, err := store.ListRenewalConfigs()
			if err != nil {
				return err
			}

			if len(configs) == 0 {
				fmt.Println("No certificate renewal configurations found.")
				return nil
			}

			fmt.Printf("Found %d certificate configurations. Checking expiration...\n", len(configs))
			for _, cfg := range configs {
				daysLeft := time.Until(cfg.ExpiresAt).Hours() / 24
				fmt.Printf("[%s] Expires in %.1f days\n", cfg.Domain, daysLeft)
				if daysLeft <= 30 || forceRenew {
					fmt.Printf("[%s] Renewal needed. Triggering renewal workflow...\n", cfg.Domain)
				} else {
					fmt.Printf("[%s] Certificate is up to date, skipping.\n", cfg.Domain)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&forceRenew, "force", false, "Force renewal regardless of expiration date")
	return cmd
}
