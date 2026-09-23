package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

// ProfileType defines CSR profile (DV, OV-FL, OV-IP, OV-YL)
type ProfileType string

const (
	ProfileDV   ProfileType = "dv"
	ProfileOVFL ProfileType = "ov-fl"
	ProfileOVIP ProfileType = "ov-ip"
	ProfileOVYL ProfileType = "ov-yl"
)

// SKZIClass defines Russian cryptographic security policy classes
type SKZIClass string

const (
	SKZIKC1 SKZIClass = "KC1"
	SKZIKC2 SKZIClass = "KC2"
	SKZIKC3 SKZIClass = "KC3"
	SKZIKB1 SKZIClass = "KB1"
	SKZIKB2 SKZIClass = "KB2"
)

// CSRConfig contains all user inputs for CSR & Key generation
type CSRConfig struct {
	Profile         ProfileType
	CommonName      string
	SANs            []string
	KeyType         string // "rsa2048", "rsa4096", "ecdsa-p256", "gost256", "gost512"
	
	// Russian Identification & Entity details
	Organization    string // O
	INN             string // ИНН ФЛ/ИП (12 digits)
	INNLE           string // ИНН ЮЛ (10 digits)
	OGRN            string // ОГРН (13 digits)
	OGRNIP          string // ОГРНИП (15 digits)
	SNILS           string // СНИЛС (11 digits)
	Surname         string // SN (Фамилия)
	GivenName       string // GN (Имя Отчество)
	Title           string // Должность (T)
	State           string // ST ("77 г. Москва")
	Locality        string // L ("г. Москва")
	Street          string // STREET
	Email           string // E
	
	// Crypto policies & tools
	SKZIClass       SKZIClass
	SubjectSignTool string // Default: "СКЗИ \"КриптоПро CSP\"" or "HSM"
}

// GenerateResult contains generated keys and CSR in PEM & DER
type GenerateResult struct {
	PrivateKeyPEM []byte
	PrivateKey    crypto.Signer
	CSRPEM        []byte
	CSRDER        []byte
}

// BuildCSR validates parameters and constructs a signed PKCS#10 CSR
func BuildCSR(cfg *CSRConfig) (*GenerateResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	kt := strings.ToLower(strings.TrimSpace(cfg.KeyType))
	if strings.HasPrefix(kt, "gost") {
		return BuildGOSTCSR(cfg, nil)
	}

	var dnsSANs []string
	var ipSANs []net.IP
	var cnAscii string
	var cnIP net.IP

	// 1. Process CN (can be DNS domain or IP)
	if cfg.CommonName != "" {
		if ip := net.ParseIP(cfg.CommonName); ip != nil {
			cnIP = ip
			cnAscii = cfg.CommonName
		} else {
			var err error
			cnAscii, err = ToPunycode(cfg.CommonName)
			if err != nil {
				return nil, fmt.Errorf("invalid commonName: %w", err)
			}
		}
	}

	hasCNInSAN := false

	for _, san := range cfg.SANs {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ipSANs = append(ipSANs, ip)
			if cnIP != nil && ip.Equal(cnIP) {
				hasCNInSAN = true
			}
			continue
		}
		asciiSAN, err := ToPunycode(san)
		if err != nil {
			return nil, fmt.Errorf("invalid SAN %q: %w", san, err)
		}
		dnsSANs = append(dnsSANs, asciiSAN)
		if cnIP == nil && strings.EqualFold(asciiSAN, cnAscii) {
			hasCNInSAN = true
		}
	}

	if !hasCNInSAN && cnAscii != "" {
		if cnIP != nil {
			ipSANs = append([]net.IP{cnIP}, ipSANs...)
		} else {
			dnsSANs = append([]string{cnAscii}, dnsSANs...)
		}
	}

	// 2. Validate Subject fields according to profile
	subject := pkix.Name{
		CommonName:   cnAscii,
		Country:      []string{"RU"},
		ExtraNames:   []pkix.AttributeTypeAndValue{},
	}

	var extraExtensions []pkix.Extension

	// Build profile-specific attributes and validate
	switch cfg.Profile {
	case ProfileDV:
		// DV only requires CN & Country RU
		if cfg.CommonName == "" {
			return nil, fmt.Errorf("commonName is required for DV certificate")
		}

	case ProfileOVFL:
		if cfg.Surname == "" || cfg.GivenName == "" {
			return nil, fmt.Errorf("surname (SN) and givenName (GN) are required for FL")
		}
		if err := ValidateINN12(cfg.INN); err != nil {
			return nil, err
		}
		if err := ValidateSNILS(cfg.SNILS); err != nil {
			return nil, err
		}
		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: cfg.Surname},
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: cfg.GivenName},
			pkix.AttributeTypeAndValue{Type: OIDINN, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.INN)}},
			pkix.AttributeTypeAndValue{Type: OIDSNILS, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(strings.ReplaceAll(strings.ReplaceAll(cfg.SNILS, "-", ""), " ", ""))}},
		)

	case ProfileOVIP:
		if cfg.Surname == "" || cfg.GivenName == "" {
			return nil, fmt.Errorf("surname (SN) and givenName (GN) are required for IP")
		}
		if err := ValidateINN12(cfg.INN); err != nil {
			return nil, err
		}
		if err := ValidateOGRNIP(cfg.OGRNIP); err != nil {
			return nil, err
		}
		if cfg.SNILS != "" {
			if err := ValidateSNILS(cfg.SNILS); err != nil {
				return nil, err
			}
			subject.ExtraNames = append(subject.ExtraNames,
				pkix.AttributeTypeAndValue{Type: OIDSNILS, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(strings.ReplaceAll(strings.ReplaceAll(cfg.SNILS, "-", ""), " ", ""))}},
			)
		}
		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: cfg.Surname},
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: cfg.GivenName},
			pkix.AttributeTypeAndValue{Type: OIDINN, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.INN)}},
			pkix.AttributeTypeAndValue{Type: OIDOGRNIP, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.OGRNIP)}},
		)

	case ProfileOVYL:
		if cfg.Organization == "" {
			return nil, fmt.Errorf("organization (O) is required for YL")
		}
		subject.Organization = []string{cfg.Organization}
		if err := ValidateINN10(cfg.INNLE); err != nil {
			return nil, err
		}
		if err := ValidateOGRN(cfg.OGRN); err != nil {
			return nil, err
		}
		if cfg.State != "" {
			if err := ValidateST(cfg.State); err != nil {
				return nil, err
			}
			subject.Province = []string{cfg.State}
		}
		if cfg.Locality != "" {
			subject.Locality = []string{cfg.Locality}
		}
		if cfg.Street != "" {
			subject.StreetAddress = []string{cfg.Street}
		}

		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: OIDINNLE, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.INNLE)}},
			pkix.AttributeTypeAndValue{Type: OIDOGRN, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.OGRN)}},
		)

	default:
		return nil, fmt.Errorf("unsupported profile %q", cfg.Profile)
	}

	if cfg.SubjectSignTool != "" {
		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: OIDSubjectSignTool, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(cfg.SubjectSignTool)}},
		)
	}

	// 3. Add KeyUsage & ExtendedKeyUsage
	// KeyUsage: Digital Signature (bit 0) | Key Encipherment (bit 2) | Key Agreement (bit 4) -> 0b10101000 = 0xA8 (BitLength: 5)
	kuBits := asn1.BitString{Bytes: []byte{0xA8}, BitLength: 5}
	kuBytes, err := asn1.Marshal(kuBits)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyUsage: %w", err)
	}
	extraExtensions = append(extraExtensions, pkix.Extension{
		Id:       OIDExtensionKeyUsage,
		Critical: true,
		Value:    kuBytes,
	})

	// ExtendedKeyUsage: serverAuth (1.3.6.1.5.5.7.3.1), clientAuth (1.3.6.1.5.5.7.3.2)
	ekuSeq := []asn1.ObjectIdentifier{OIDServerAuth, OIDClientAuth}
	ekuBytes, err := asn1.Marshal(ekuSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal extendedKeyUsage: %w", err)
	}
	extraExtensions = append(extraExtensions, pkix.Extension{
		Id:       OIDExtensionExtendedKeyUsage,
		Critical: false,
		Value:    ekuBytes,
	})

	// 4. Add Certificate Policies if SKZIClass or Profile is set
	var policyOIDs []asn1.ObjectIdentifier
	if cfg.Profile == ProfileDV {
		policyOIDs = append(policyOIDs, OIDPolicyDV)
	} else {
		policyOIDs = append(policyOIDs, OIDPolicyOV)
	}

	switch cfg.SKZIClass {
	case SKZIKC1:
		policyOIDs = append(policyOIDs, OIDPolicyKC1)
	case SKZIKC2:
		policyOIDs = append(policyOIDs, OIDPolicyKC2)
	case SKZIKC3:
		policyOIDs = append(policyOIDs, OIDPolicyKC3)
	case SKZIKB1:
		policyOIDs = append(policyOIDs, OIDPolicyKB1)
	case SKZIKB2:
		policyOIDs = append(policyOIDs, OIDPolicyKB2)
	}

	if len(policyOIDs) > 0 {
		type policyInformation struct {
			Policy asn1.ObjectIdentifier
		}
		var policies []policyInformation
		for _, oid := range policyOIDs {
			policies = append(policies, policyInformation{Policy: oid})
		}
		cpBytes, err := asn1.Marshal(policies)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificatePolicies: %w", err)
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       OIDExtensionCertificatePolicies,
			Critical: false,
			Value:    cpBytes,
		})
	}

	// 5. Generate Private Key
	signer, privPEM, err := generateKey(cfg.KeyType)
	if err != nil {
		return nil, err
	}

	// 6. Create Certificate Request Template
	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsSANs,
		IPAddresses:        ipSANs,
		ExtraExtensions:    extraExtensions,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if _, ok := signer.(*ecdsa.PrivateKey); ok {
		csrTemplate.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return &GenerateResult{
		PrivateKeyPEM: privPEM,
		PrivateKey:    signer,
		CSRPEM:        csrPEM,
		CSRDER:        csrDER,
	}, nil
}

func generateKey(keyType string) (crypto.Signer, []byte, error) {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	if keyType == "" || keyType == "rsa2048" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA 2048 key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		return priv, pemBytes, nil
	} else if keyType == "rsa4096" {
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA 4096 key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		return priv, pemBytes, nil
	} else if keyType == "ecdsa" || keyType == "ecdsa-p256" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
		return priv, pemBytes, nil
	}
	return nil, nil, fmt.Errorf("unsupported key type %q (use rsa2048, rsa4096, ecdsa-p256)", keyType)
}
