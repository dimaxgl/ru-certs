package csr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// LintReport contains issues found in CSR verification
type LintReport struct {
	IsValid   bool
	Errors    []string
	Warnings  []string
	Subject   string
	SANs      []string
	KeyType   string
	Signature string
}

// LintCSR parses and checks a CSR PEM or DER against NUC Russian rules
func LintCSR(raw []byte) (*LintReport, error) {
	var derBytes []byte
	block, _ := pem.Decode(raw)
	if block != nil {
		derBytes = block.Bytes
	} else {
		derBytes = raw
	}

	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	report := &LintReport{
		IsValid:   true,
		Subject:   csr.Subject.String(),
		SANs:      csr.DNSNames,
		Signature: csr.SignatureAlgorithm.String(),
	}

	// 1. Check Country = RU
	hasRU := false
	for _, c := range csr.Subject.Country {
		if c == "RU" {
			hasRU = true
			break
		}
	}
	if !hasRU {
		report.Warnings = append(report.Warnings, "Country (C) should be 'RU' for Russian CA compliance")
	}

	// 2. Check CommonName
	if csr.Subject.CommonName == "" {
		report.Errors = append(report.Errors, "CommonName (CN) is missing in Subject")
	}

	// 3. Inspect ExtraNames for Russian OIDs
	for _, atv := range csr.Subject.Names {
		oidStr := atv.Type.String()
		valStr, ok := atv.Value.(string)
		if !ok {
			continue
		}

		if atv.Type.Equal(OIDINNLE) {
			if err := ValidateINN10(valStr); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid INN LE (OID %s): %v", oidStr, err))
			}
		} else if atv.Type.Equal(OIDINN) {
			if err := ValidateINN12(valStr); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid INN (OID %s): %v", oidStr, err))
			}
		} else if atv.Type.Equal(OIDOGRN) {
			if err := ValidateOGRN(valStr); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid OGRN (OID %s): %v", oidStr, err))
			}
		} else if atv.Type.Equal(OIDOGRNIP) {
			if err := ValidateOGRNIP(valStr); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid OGRNIP (OID %s): %v", oidStr, err))
			}
		} else if atv.Type.Equal(OIDSNILS) {
			if err := ValidateSNILS(valStr); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid SNILS (OID %s): %v", oidStr, err))
			}
		}
	}

	if len(report.Errors) > 0 {
		report.IsValid = false
	}

	return report, nil
}

// FormatSummary returns formatted diagnostic text
func (r *LintReport) FormatSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subject: %s\n", r.Subject)
	fmt.Fprintf(&b, "SANs: %s\n", strings.Join(r.SANs, ", "))
	fmt.Fprintf(&b, "Signature Algorithm: %s\n", r.Signature)
	fmt.Fprintf(&b, "Valid: %t\n", r.IsValid)
	if len(r.Errors) > 0 {
		b.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  - [FAIL] %s\n", e)
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - [WARN] %s\n", w)
		}
	}
	return b.String()
}
