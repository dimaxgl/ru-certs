package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dimaxgl/ru-certs/pkg/configgen"
	"github.com/spf13/cobra"
)

var (
	configDomain  string
	configOutFile string
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate web server (Nginx, Traefik) multi-certificate configuration snippets",
	}

	nginxCmd := &cobra.Command{
		Use:   "nginx",
		Short: "Generate Nginx multi-certificate configuration snippet",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configDomain == "" {
				return fmt.Errorf("domain must be specified via -d / --domain")
			}

			out, err := configgen.GenerateNginxConfig(cfgDir, configDomain, true, true, true)
			if err != nil {
				return err
			}

			if configOutFile != "" {
				dir := filepath.Dir(configOutFile)
				if err := os.MkdirAll(dir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(configOutFile, []byte(out), 0644); err != nil {
					return err
				}
				fmt.Printf("Nginx configuration written to %s\n", configOutFile)
			} else {
				fmt.Println(out)
			}
			return nil
		},
	}

	traefikCmd := &cobra.Command{
		Use:   "traefik",
		Short: "Generate Traefik dynamic TLS configuration YAML",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configDomain == "" {
				return fmt.Errorf("domain must be specified via -d / --domain")
			}

			out, err := configgen.GenerateTraefikConfig(cfgDir, configDomain, true, true, false)
			if err != nil {
				return err
			}

			if configOutFile != "" {
				dir := filepath.Dir(configOutFile)
				if err := os.MkdirAll(dir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(configOutFile, []byte(out), 0644); err != nil {
					return err
				}
				fmt.Printf("Traefik configuration written to %s\n", configOutFile)
			} else {
				fmt.Println(out)
			}
			return nil
		},
	}

	for _, sub := range []*cobra.Command{nginxCmd, traefikCmd} {
		sub.Flags().StringVarP(&configDomain, "domain", "d", "", "Domain name for configuration")
		sub.Flags().StringVarP(&configOutFile, "output", "o", "", "Output configuration file path")
	}

	cmd.AddCommand(nginxCmd)
	cmd.AddCommand(traefikCmd)
	return cmd
}
