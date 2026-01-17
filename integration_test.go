//go:build integration

package cymruasn

import (
	"context"
	"testing"
	"time"
)

func TestIntegrationLookup(t *testing.T) {
	client := NewClient(
		WithTimeout(30 * time.Second),
	)

	ips := []string{"8.8.8.8", "1.1.1.1"}

	resp, err := client.Lookup(context.Background(), ips)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}

	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}

	if len(resp.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(resp.Errors))
		for _, e := range resp.Errors {
			t.Logf("error: %s: %v", e.IP, e.Err)
		}
	}

	for _, r := range resp.Results {
		t.Logf("IP: %s, ASN: %d, Prefix: %s, CC: %s, Name: %s",
			r.IP, r.ASN, r.BGPPrefix, r.CountryCode, r.ASName)

		if r.ASN == 0 {
			t.Errorf("expected non-zero ASN for %s", r.IP)
		}

		if r.IP == "8.8.8.8" && r.ASN != 15169 {
			t.Errorf("expected ASN 15169 for 8.8.8.8, got %d", r.ASN)
		}

		if r.IP == "1.1.1.1" && r.ASN != 13335 {
			t.Errorf("expected ASN 13335 for 1.1.1.1, got %d", r.ASN)
		}
	}
}

func TestIntegrationIPv6(t *testing.T) {
	client := NewClient(
		WithTimeout(30 * time.Second),
	)

	ips := []string{"2001:4860:4860::8888"}

	resp, err := client.Lookup(context.Background(), ips)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}

	if len(resp.Results) == 0 {
		t.Log("no results for IPv6 - may not be supported by server")
		return
	}

	for _, r := range resp.Results {
		t.Logf("IPv6 result - IP: %s, ASN: %d, Prefix: %s, CC: %s, Name: %s",
			r.IP, r.ASN, r.BGPPrefix, r.CountryCode, r.ASName)
	}
}
