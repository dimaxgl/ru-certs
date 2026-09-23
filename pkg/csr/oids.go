package csr

import "encoding/asn1"

var (
	// Russian Identification OIDs
	OIDOGRN   = asn1.ObjectIdentifier{1, 2, 643, 100, 1}   // ОГРН ЮЛ (13 digits)
	OIDSNILS  = asn1.ObjectIdentifier{1, 2, 643, 100, 3}   // СНИЛС (11 digits)
	OIDINNLE  = asn1.ObjectIdentifier{1, 2, 643, 100, 4}   // ИНН ЮЛ (10 digits)
	OIDOGRNIP = asn1.ObjectIdentifier{1, 2, 643, 100, 5}   // ОГРНИП (15 digits)
	OIDINN    = asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1} // ИНН ФЛ/ИП (12 digits)

	// Technical & Tool Identification OIDs
	OIDSubjectSignTool = asn1.ObjectIdentifier{1, 2, 643, 100, 111} // Средство электронной подписи

	// Standard Certificate Extensions
	OIDExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtensionExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

	// Extended Key Usage Purpose OIDs
	OIDServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}

	// NUC / Минцифры Certificate Policies OIDs
	OIDPolicyDV = asn1.ObjectIdentifier{1, 2, 643, 2, 25, 1, 14, 1} // Доверительный сертификат DV
	OIDPolicyOV = asn1.ObjectIdentifier{1, 2, 643, 2, 25, 1, 14, 2} // Доверительный сертификат OV

	// Cryptographic Protection Classes (СКЗИ)
	OIDPolicyKC1 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 1}
	OIDPolicyKC2 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 2}
	OIDPolicyKC3 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 3}
	OIDPolicyKB1 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 4}
	OIDPolicyKB2 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 5}
)
