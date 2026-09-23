package csr

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var (
	reDigitsOnly = regexp.MustCompile(`^\d+$`)
	reSTFormat   = regexp.MustCompile(`^\d{2}\s+.+`) // e.g. "77 г. Москва" or "78 г. Санкт-Петербург"
)

// ValidateINN10 checks 10-digit INN for Legal Entities (ЮЛ)
func ValidateINN10(inn string) error {
	inn = strings.TrimSpace(inn)
	if len(inn) != 10 || !reDigitsOnly.MatchString(inn) {
		return fmt.Errorf("INN LE must be exactly 10 digits, got %q", inn)
	}
	// Checksum calculation (N10)
	weights := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(inn[i]-'0') * weights[i]
	}
	n10 := (sum % 11) % 10
	if n10 != int(inn[9]-'0') {
		return fmt.Errorf("invalid INN LE checksum for %q (expected %d, got %c)", inn, n10, inn[9])
	}
	return nil
}

// ValidateINN12 checks 12-digit INN for Natural Persons (ФЛ) and Sole Proprietors (ИП)
func ValidateINN12(inn string) error {
	inn = strings.TrimSpace(inn)
	if len(inn) != 12 || !reDigitsOnly.MatchString(inn) {
		return fmt.Errorf("INN must be exactly 12 digits, got %q", inn)
	}
	// Checksum N11
	w11 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s11 := 0
	for i := 0; i < 10; i++ {
		s11 += int(inn[i]-'0') * w11[i]
	}
	n11 := (s11 % 11) % 10
	if n11 != int(inn[10]-'0') {
		return fmt.Errorf("invalid INN checksum (digit 11) for %q", inn)
	}

	// Checksum N12
	w12 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s12 := 0
	for i := 0; i < 11; i++ {
		s12 += int(inn[i]-'0') * w12[i]
	}
	n12 := (s12 % 11) % 10
	if n12 != int(inn[11]-'0') {
		return fmt.Errorf("invalid INN checksum (digit 12) for %q", inn)
	}
	return nil
}

// ValidateOGRN checks 13-digit OGRN for Legal Entities
func ValidateOGRN(ogrn string) error {
	ogrn = strings.TrimSpace(ogrn)
	if len(ogrn) != 13 || !reDigitsOnly.MatchString(ogrn) {
		return fmt.Errorf("OGRN must be exactly 13 digits, got %q", ogrn)
	}
	var num int64
	for i := 0; i < 12; i++ {
		num = num*10 + int64(ogrn[i]-'0')
	}
	chk := int(num % 11 % 10)
	if chk != int(ogrn[12]-'0') {
		return fmt.Errorf("invalid OGRN checksum for %q (expected %d, got %c)", ogrn, chk, ogrn[12])
	}
	return nil
}

// ValidateOGRNIP checks 15-digit OGRNIP for Sole Proprietors
func ValidateOGRNIP(ogrnip string) error {
	ogrnip = strings.TrimSpace(ogrnip)
	if len(ogrnip) != 15 || !reDigitsOnly.MatchString(ogrnip) {
		return fmt.Errorf("OGRNIP must be exactly 15 digits, got %q", ogrnip)
	}
	var num int64
	for i := 0; i < 14; i++ {
		num = num*10 + int64(ogrnip[i]-'0')
	}
	chk := int(num % 13 % 10)
	if chk != int(ogrnip[14]-'0') {
		return fmt.Errorf("invalid OGRNIP checksum for %q (expected %d, got %c)", ogrnip, chk, ogrnip[14])
	}
	return nil
}

// ValidateSNILS checks 11-digit SNILS
func ValidateSNILS(snils string) error {
	// Strip spaces and dashes if any
	snils = strings.ReplaceAll(snils, " ", "")
	snils = strings.ReplaceAll(snils, "-", "")
	if len(snils) != 11 || !reDigitsOnly.MatchString(snils) {
		return fmt.Errorf("SNILS must be exactly 11 digits, got %q", snils)
	}
	var num int64
	for i := 0; i < 9; i++ {
		num = num*10 + int64(snils[i]-'0')
	}
	if num <= 1001998 {
		// Special exemption for initial ranges
		return nil
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(snils[i]-'0') * (9 - i)
	}
	var chk int
	if sum < 100 {
		chk = sum
	} else if sum == 100 || sum == 101 {
		chk = 0
	} else {
		rem := sum % 101
		if rem < 100 {
			chk = rem
		} else {
			chk = 0
		}
	}
	actual := int(snils[9]-'0')*10 + int(snils[10]-'0')
	if chk != actual {
		return fmt.Errorf("invalid SNILS checksum for %q (expected %02d, got %02d)", snils, chk, actual)
	}
	return nil
}

// ValidateST checks Russian state/region format (e.g. "77 г. Москва")
func ValidateST(st string) error {
	st = strings.TrimSpace(st)
	if !reSTFormat.MatchString(st) {
		return fmt.Errorf("ST (State/Region) must start with a 2-digit region code followed by space and name (e.g. '77 г. Москва'), got %q", st)
	}
	return nil
}

// ToPunycode converts IDN / Cyrillic domains to ASCII punycode (e.g. "сайт.рф" -> "xn--80aswg.xn--p1ai")
func ToPunycode(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	// Handle wildcard prefix
	prefix := ""
	if strings.HasPrefix(domain, "*.") {
		prefix = "*."
		domain = domain[2:]
	}
	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("failed to convert domain %q to ASCII: %w", domain, err)
	}
	return prefix + asciiDomain, nil
}
