package csr

import (
	"strings"
	"testing"
)

func TestValidateINN10(t *testing.T) {
	tests := []struct {
		name    string
		inn     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 10-digit INN",
			inn:     "7707083893", // Sberbank
			wantErr: false,
		},
		{
			name:    "valid with surrounding whitespace",
			inn:     "  7707083893  ",
			wantErr: false,
		},
		{
			name:    "invalid length - 9 digits",
			inn:     "770708389",
			wantErr: true,
			errMsg:  "must be exactly 10 digits",
		},
		{
			name:    "invalid length - 11 digits",
			inn:     "77070838931",
			wantErr: true,
			errMsg:  "must be exactly 10 digits",
		},
		{
			name:    "non-numeric characters",
			inn:     "770708389a",
			wantErr: true,
			errMsg:  "must be exactly 10 digits",
		},
		{
			name:    "invalid checksum",
			inn:     "7707083894",
			wantErr: true,
			errMsg:  "invalid INN LE checksum",
		},
		{
			name:    "checksum result mod 11 == 10 check (n10=0)",
			inn:     "7707083893",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateINN10(tc.inn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateINN12(t *testing.T) {
	tests := []struct {
		name    string
		inn     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 12-digit INN",
			inn:     "500100732259",
			wantErr: false,
		},
		{
			name:    "valid 12-digit with spaces",
			inn:     "  500100732259  ",
			wantErr: false,
		},
		{
			name:    "invalid length - 10 digits",
			inn:     "7707083893",
			wantErr: true,
			errMsg:  "must be exactly 12 digits",
		},
		{
			name:    "non-numeric characters",
			inn:     "50010073225x",
			wantErr: true,
			errMsg:  "must be exactly 12 digits",
		},
		{
			name:    "invalid checksum first check digit (n11)",
			inn:     "500100732249",
			wantErr: true,
			errMsg:  "invalid INN checksum (digit 11)",
		},
		{
			name:    "invalid checksum second check digit (n12)",
			inn:     "500100732258",
			wantErr: true,
			errMsg:  "invalid INN checksum (digit 12)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateINN12(tc.inn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateOGRN(t *testing.T) {
	tests := []struct {
		name    string
		ogrn    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 13-digit OGRN",
			ogrn:    "1027700132195",
			wantErr: false,
		},
		{
			name:    "valid with surrounding whitespace",
			ogrn:    "  1027700132195  ",
			wantErr: false,
		},
		{
			name:    "invalid length - 12 digits",
			ogrn:    "102770013219",
			wantErr: true,
			errMsg:  "must be exactly 13 digits",
		},
		{
			name:    "invalid length - 14 digits",
			ogrn:    "10277001321955",
			wantErr: true,
			errMsg:  "must be exactly 13 digits",
		},
		{
			name:    "non-numeric characters",
			ogrn:    "102770013219A",
			wantErr: true,
			errMsg:  "must be exactly 13 digits",
		},
		{
			name:    "invalid checksum",
			ogrn:    "1027700132194",
			wantErr: true,
			errMsg:  "invalid OGRN checksum",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOGRN(tc.ogrn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateOGRNIP(t *testing.T) {
	tests := []struct {
		name    string
		ogrnip  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 15-digit OGRNIP",
			ogrnip:  "304500116000157",
			wantErr: false,
		},
		{
			name:    "valid with whitespace",
			ogrnip:  " 304500116000157 ",
			wantErr: false,
		},
		{
			name:    "invalid length - 14 digits",
			ogrnip:  "30450011600015",
			wantErr: true,
			errMsg:  "must be exactly 15 digits",
		},
		{
			name:    "non-numeric characters",
			ogrnip:  "30450011600015b",
			wantErr: true,
			errMsg:  "must be exactly 15 digits",
		},
		{
			name:    "invalid checksum",
			ogrnip:  "304500116000158",
			wantErr: true,
			errMsg:  "invalid OGRNIP checksum",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOGRNIP(tc.ogrnip)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateSNILS(t *testing.T) {
	tests := []struct {
		name    string
		snils   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid formatted SNILS",
			snils:   "112-233-445 95",
			wantErr: false,
		},
		{
			name:    "valid raw digits SNILS",
			snils:   "11223344595",
			wantErr: false,
		},
		{
			name:    "number <= 001001998 skip checksum",
			snils:   "001-001-998 00",
			wantErr: false,
		},
		{
			name:    "checksum sum == 100 or 101 gives 00",
			snils:   "087-654-303 00",
			wantErr: false,
		},
		{
			name:    "invalid length",
			snils:   "112-233-445",
			wantErr: true,
			errMsg:  "must be exactly 11 digits",
		},
		{
			name:    "non-numeric after stripping separators",
			snils:   "112-233-445 9a",
			wantErr: true,
			errMsg:  "must be exactly 11 digits",
		},
		{
			name:    "invalid checksum",
			snils:   "112-233-445 96",
			wantErr: true,
			errMsg:  "invalid SNILS checksum",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSNILS(tc.snils)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateST(t *testing.T) {
	tests := []struct {
		name    string
		st      string
		wantErr bool
	}{
		{
			name:    "valid code with region name",
			st:      "77 г. Москва",
			wantErr: false,
		},
		{
			name:    "valid 78 region",
			st:      "78 г. Санкт-Петербург",
			wantErr: false,
		},
		{
			name:    "valid with leading/trailing spaces",
			st:      "  50 Московская область  ",
			wantErr: false,
		},
		{
			name:    "too short",
			st:      "7",
			wantErr: true,
		},
		{
			name:    "only 2 digits without region name",
			st:      "77",
			wantErr: true,
		},
		{
			name:    "invalid non-digit prefix",
			st:      "XX Москва",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateST(tc.st)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for ST %q, got nil", tc.st)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for ST %q: %v", tc.st, err)
			}
		})
	}
}

func TestToPunycode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "ascii domain",
			input:    "example.com",
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "cyrillic domain .рф",
			input:    "президент.рф",
			expected: "xn--d1abbgf6aiiy.xn--p1ai",
			wantErr:  false,
		},
		{
			name:     "cyrillic wildcard domain *.сайт.рф",
			input:    "*.сайт.рф",
			expected: "*.xn--80aswg.xn--p1ai",
			wantErr:  false,
		},
		{
			name:     "mixed ascii and cyrillic",
			input:    "тест.example.com",
			expected: "xn--e1aybc.example.com",
			wantErr:  false,
		},
		{
			name:     "empty domain",
			input:    "   ",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToPunycode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %q, want %q", got, tc.expected)
			}
		})
	}
}
