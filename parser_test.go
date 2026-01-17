package cymruasn

import (
	"testing"
)

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
		checkFunc func(t *testing.T, results []Result)
	}{
		{
			name: "valid bulk response",
			input: `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
15169   | 8.8.8.8          | 8.8.8.0/24       | US | GOOGLE, US
13335   | 1.1.1.1          | 1.1.1.0/24       | US | CLOUDFLARE, US`,
			wantCount: 2,
			wantErr:   false,
			checkFunc: func(t *testing.T, results []Result) {
				if results[0].ASN != 15169 {
					t.Errorf("expected ASN 15169, got %d", results[0].ASN)
				}
				if results[0].IP != "8.8.8.8" {
					t.Errorf("expected IP 8.8.8.8, got %s", results[0].IP)
				}
				if results[0].CountryCode != "US" {
					t.Errorf("expected CC US, got %s", results[0].CountryCode)
				}
				if results[1].ASN != 13335 {
					t.Errorf("expected ASN 13335, got %d", results[1].ASN)
				}
			},
		},
		{
			name: "response with header line",
			input: `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
AS      | IP               | BGP Prefix       | CC | AS Name
15169   | 8.8.8.8          | 8.8.8.0/24       | US | GOOGLE, US`,
			wantCount: 1,
			wantErr:   false,
			checkFunc: func(t *testing.T, results []Result) {
				if results[0].ASN != 15169 {
					t.Errorf("expected ASN 15169, got %d", results[0].ASN)
				}
			},
		},
		{
			name:      "empty response",
			input:     "",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "NA ASN value",
			input: `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
NA      | 192.0.2.1        | NA               | ZZ | NA`,
			wantCount: 1,
			wantErr:   false,
			checkFunc: func(t *testing.T, results []Result) {
				if results[0].ASN != 0 {
					t.Errorf("expected ASN 0 for NA, got %d", results[0].ASN)
				}
			},
		},
		{
			name: "whitespace handling",
			input: `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
  15169  |  8.8.8.8  |  8.8.8.0/24  |  US  |  GOOGLE, US  `,
			wantCount: 1,
			wantErr:   false,
			checkFunc: func(t *testing.T, results []Result) {
				if results[0].IP != "8.8.8.8" {
					t.Errorf("expected trimmed IP 8.8.8.8, got '%s'", results[0].IP)
				}
				if results[0].CountryCode != "US" {
					t.Errorf("expected trimmed CC US, got '%s'", results[0].CountryCode)
				}
			},
		},
		{
			name: "minimal fields",
			input: `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
15169 | 8.8.8.8`,
			wantCount: 1,
			wantErr:   false,
			checkFunc: func(t *testing.T, results []Result) {
				if results[0].ASN != 15169 {
					t.Errorf("expected ASN 15169, got %d", results[0].ASN)
				}
				if results[0].BGPPrefix != "" {
					t.Errorf("expected empty BGPPrefix, got %s", results[0].BGPPrefix)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := parseResponse([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(results) != tt.wantCount {
				t.Errorf("expected %d results, got %d", tt.wantCount, len(results))
				return
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, results)
			}
		})
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    Result
		wantErr bool
	}{
		{
			name: "full line",
			line: "15169 | 8.8.8.8 | 8.8.8.0/24 | US | GOOGLE, US",
			want: Result{
				ASN:         15169,
				IP:          "8.8.8.8",
				BGPPrefix:   "8.8.8.0/24",
				CountryCode: "US",
				ASName:      "GOOGLE, US",
			},
			wantErr: false,
		},
		{
			name:    "invalid - no pipe",
			line:    "just some text",
			wantErr: true,
		},
		{
			name:    "invalid ASN",
			line:    "notanumber | 8.8.8.8",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLine(tt.line)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got.ASN != tt.want.ASN {
				t.Errorf("ASN: got %d, want %d", got.ASN, tt.want.ASN)
			}
			if got.IP != tt.want.IP {
				t.Errorf("IP: got %s, want %s", got.IP, tt.want.IP)
			}
			if got.BGPPrefix != tt.want.BGPPrefix {
				t.Errorf("BGPPrefix: got %s, want %s", got.BGPPrefix, tt.want.BGPPrefix)
			}
			if got.CountryCode != tt.want.CountryCode {
				t.Errorf("CountryCode: got %s, want %s", got.CountryCode, tt.want.CountryCode)
			}
			if got.ASName != tt.want.ASName {
				t.Errorf("ASName: got %s, want %s", got.ASName, tt.want.ASName)
			}
		})
	}
}

func TestIsHeaderLine(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"AS      | IP               | BGP Prefix       | CC | AS Name", true},
		{"as | ip | prefix | cc | as name", true},
		{"15169 | 8.8.8.8 | 8.8.8.0/24 | US | GOOGLE", false},
		{"Bulk mode; whois.cymru.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := isHeaderLine(tt.line); got != tt.want {
				t.Errorf("isHeaderLine(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}
