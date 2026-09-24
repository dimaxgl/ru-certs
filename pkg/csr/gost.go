package csr

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
)

var (
	// OID for GOST R 34.10-2012 256-bit Public Key
	OIDPublicKeyGOST3410_2012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// OID for GOST R 34.10-2012 512-bit Public Key
	OIDPublicKeyGOST3410_2012_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

	// OID for GOST R 34.10-2012 with GOST R 34.11-2012 256-bit Signature
	OIDSignatureGOST3410_2012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	// OID for GOST R 34.10-2012 with GOST R 34.11-2012 512-bit Signature
	OIDSignatureGOST3410_2012_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}

	// GOST Curve 2012 Paramsets
	OIDParamSet2012_256_A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	OIDParamSet2012_512_A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	OIDDigest2012_256     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	OIDDigest2012_512     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

type GOSTPrivateKey struct {
	CurveSize int // 256 or 512
	Prv       *gost3410.PrivateKey
}

type GOSTPublicKeyInfo struct {
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type GOSTParams struct {
	Curve  asn1.ObjectIdentifier
	Digest asn1.ObjectIdentifier `asn1:"optional"`
}

// GenerateGOSTKey generates a GOST R 34.10-2012 private key
func GenerateGOSTKey(curveSize int) (*GOSTPrivateKey, error) {
	var curve *gost3410.Curve
	if curveSize == 512 {
		curve = gost3410.CurveIdtc26gost34102012512paramSetA()
	} else {
		curve = gost3410.CurveIdtc26gost34102012256paramSetA()
		curveSize = 256
	}

	prv, err := gost3410.GenPrivateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate GOST key: %w", err)
	}

	return &GOSTPrivateKey{
		CurveSize: curveSize,
		Prv:       prv,
	}, nil
}

// EncodePrivatePEM encodes GOST private key to PEM format
func (k *GOSTPrivateKey) EncodePrivatePEM() []byte {
	raw := k.Prv.Raw()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "GOST2012 PRIVATE KEY",
		Bytes: raw,
	})
}

type certificationRequestInfo struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  GOSTPublicKeyInfo
	Attributes []asn1.RawValue `asn1:"tag:0,optional"`
}

type certificationRequest struct {
	TBSCSR             certificationRequestInfo
	SignatureAlgorithm pkixAlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// BuildGOSTCSR generates a complete PKCS#10 Certificate Signing Request using GOST 2012
func BuildGOSTCSR(cfg *CSRConfig, key *GOSTPrivateKey) (*GenerateResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if key == nil {
		curveSize := 256
		if strings.Contains(strings.ToLower(cfg.KeyType), "512") {
			curveSize = 512
		}
		var err error
		key, err = GenerateGOSTKey(curveSize)
		if err != nil {
			return nil, err
		}
	}

	// 1. Process SANs and CN
	var dnsSANs []string
	var ipSANs []net.IP
	var cnAscii string
	var cnIP net.IP

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

	// 2. Build Subject RDNs
	subject := pkix.Name{
		CommonName: cnAscii,
		Country:    []string{"RU"},
		ExtraNames: []pkix.AttributeTypeAndValue{},
	}

	switch cfg.Profile {
	case ProfileDV:
		if cfg.CommonName == "" {
			return nil, fmt.Errorf("commonName is required for DV")
		}
	case ProfileOVFL:
		if cfg.Surname == "" || cfg.GivenName == "" {
			return nil, fmt.Errorf("surname and givenName are required for FL")
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
			return nil, fmt.Errorf("surname and givenName are required for IP")
		}
		if err := ValidateINN12(cfg.INN); err != nil {
			return nil, err
		}
		if err := ValidateOGRNIP(cfg.OGRNIP); err != nil {
			return nil, err
		}
		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: cfg.Surname},
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: cfg.GivenName},
			pkix.AttributeTypeAndValue{Type: OIDINN, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.INN)}},
			pkix.AttributeTypeAndValue{Type: OIDOGRNIP, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(cfg.OGRNIP)}},
		)
	case ProfileOVYL:
		if cfg.Organization == "" {
			return nil, fmt.Errorf("organization is required for YL")
		}
		subject.Organization = []string{cfg.Organization}
		if err := ValidateINN10(cfg.INNLE); err != nil {
			return nil, err
		}
		if err := ValidateOGRN(cfg.OGRN); err != nil {
			return nil, err
		}
		if cfg.State != "" {
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

	subjBytes, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject failed: %w", err)
	}

	// 3. Prepare Extensions
	var extraExtensions []pkix.Extension

	// SAN extension
	if len(dnsSANs) > 0 || len(ipSANs) > 0 {
		var rawValues []asn1.RawValue
		for _, name := range dnsSANs {
			rawValues = append(rawValues, asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        2, // dNSName
				IsCompound: false,
				Bytes:      []byte(name),
			})
		}
		for _, ip := range ipSANs {
			rawValues = append(rawValues, asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        7, // iPAddress
				IsCompound: false,
				Bytes:      ip,
			})
		}
		sanBytes, err := asn1.Marshal(rawValues)
		if err != nil {
			return nil, fmt.Errorf("marshal SAN failed: %w", err)
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       OIDExtensionSubjectAltName,
			Critical: false,
			Value:    sanBytes,
		})
	}

	// Key Usage
	kuBits := asn1.BitString{Bytes: []byte{0xA8}, BitLength: 5}
	kuBytes, err := asn1.Marshal(kuBits)
	if err != nil {
		return nil, fmt.Errorf("marshal keyUsage failed: %w", err)
	}
	extraExtensions = append(extraExtensions, pkix.Extension{
		Id:       OIDExtensionKeyUsage,
		Critical: true,
		Value:    kuBytes,
	})

	// EKU
	ekuSeq := []asn1.ObjectIdentifier{OIDServerAuth, OIDClientAuth}
	ekuBytes, err := asn1.Marshal(ekuSeq)
	if err != nil {
		return nil, fmt.Errorf("marshal eku failed: %w", err)
	}
	extraExtensions = append(extraExtensions, pkix.Extension{
		Id:       OIDExtensionExtendedKeyUsage,
		Critical: false,
		Value:    ekuBytes,
	})

	// Certificate Policies
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
		cpBytes, _ := asn1.Marshal(policies)
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       OIDExtensionCertificatePolicies,
			Critical: false,
			Value:    cpBytes,
		})
	}

	extSeqBytes, err := asn1.Marshal(extraExtensions)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions failed: %w", err)
	}

	// 4. Public Key
	pubKey, err := key.Prv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	pubRaw := pubKey.Raw()

	algOID := OIDPublicKeyGOST3410_2012_256
	sigAlgOID := OIDSignatureGOST3410_2012_256
	curveOID := OIDParamSet2012_256_A
	digestOID := OIDDigest2012_256

	if key.CurveSize == 512 {
		algOID = OIDPublicKeyGOST3410_2012_512
		sigAlgOID = OIDSignatureGOST3410_2012_512
		curveOID = OIDParamSet2012_512_A
		digestOID = OIDDigest2012_512
	}

	pubOctets, err := asn1.Marshal(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("marshal pub key failed: %w", err)
	}

	params := GOSTParams{
		Curve:  curveOID,
		Digest: digestOID,
	}
	paramsBytes, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params failed: %w", err)
	}

	spki := GOSTPublicKeyInfo{
		Algorithm: pkixAlgorithmIdentifier{
			Algorithm: algOID,
			Parameters: asn1.RawValue{
				FullBytes: paramsBytes,
			},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubOctets,
			BitLength: len(pubOctets) * 8,
		},
	}

	// 5. Construct TBS CSR
	cri := certificationRequestInfo{
		Version:   0,
		Subject:   asn1.RawValue{FullBytes: subjBytes},
		PublicKey: spki,
		Attributes: []asn1.RawValue{
			{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      extSeqBytes,
			},
		},
	}

	tbsBytes, err := asn1.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("marshal tbs csr failed: %w", err)
	}

	// 6. Sign TBS bytes
	var sigBytes []byte
	if key.CurveSize == 512 {
		h := gost34112012512.New()
		h.Write(tbsBytes)
		digest := h.Sum(nil)
		sigBytes, err = key.Prv.Sign(rand.Reader, digest, nil)
		if err != nil {
			return nil, fmt.Errorf("gost 512 sign failed: %w", err)
		}
	} else {
		h := gost34112012256.New()
		h.Write(tbsBytes)
		digest := h.Sum(nil)
		sigBytes, err = key.Prv.Sign(rand.Reader, digest, nil)
		if err != nil {
			return nil, fmt.Errorf("gost 256 sign failed: %w", err)
		}
	}

	csrObj := certificationRequest{
		TBSCSR: cri,
		SignatureAlgorithm: pkixAlgorithmIdentifier{
			Algorithm: sigAlgOID,
			Parameters: asn1.RawValue{
				Tag: asn1.TagNull,
			},
		},
		SignatureValue: asn1.BitString{
			Bytes:     sigBytes,
			BitLength: len(sigBytes) * 8,
		},
	}

	csrDER, err := asn1.Marshal(csrObj)
	if err != nil {
		return nil, fmt.Errorf("marshal final csr failed: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return &GenerateResult{
		PrivateKeyPEM: key.EncodePrivatePEM(),
		CSRPEM:        csrPEM,
		CSRDER:        csrDER,
	}, nil
}
