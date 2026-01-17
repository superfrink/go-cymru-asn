package cymruasn

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		c := NewClient()
		if c.server != DefaultServer {
			t.Errorf("expected server %s, got %s", DefaultServer, c.server)
		}
		if c.port != DefaultPort {
			t.Errorf("expected port %s, got %s", DefaultPort, c.port)
		}
		if c.timeout != DefaultTimeout {
			t.Errorf("expected timeout %v, got %v", DefaultTimeout, c.timeout)
		}
	})

	t.Run("with options", func(t *testing.T) {
		c := NewClient(
			WithServer("test.example.com"),
			WithPort("8080"),
			WithTimeout(5*time.Second),
		)
		if c.server != "test.example.com" {
			t.Errorf("expected server test.example.com, got %s", c.server)
		}
		if c.port != "8080" {
			t.Errorf("expected port 8080, got %s", c.port)
		}
		if c.timeout != 5*time.Second {
			t.Errorf("expected timeout 5s, got %v", c.timeout)
		}
	})
}

func TestValidateIPs(t *testing.T) {
	c := NewClient()

	tests := []struct {
		name         string
		ips          []string
		wantValid    int
		wantInvalid  int
	}{
		{
			name:        "all valid IPv4",
			ips:         []string{"8.8.8.8", "1.1.1.1"},
			wantValid:   2,
			wantInvalid: 0,
		},
		{
			name:        "all valid IPv6",
			ips:         []string{"2001:4860:4860::8888", "2606:4700:4700::1111"},
			wantValid:   2,
			wantInvalid: 0,
		},
		{
			name:        "mixed valid and invalid",
			ips:         []string{"8.8.8.8", "not-an-ip", "1.1.1.1"},
			wantValid:   2,
			wantInvalid: 1,
		},
		{
			name:        "all invalid",
			ips:         []string{"invalid", "also-invalid"},
			wantValid:   0,
			wantInvalid: 2,
		},
		{
			name:        "empty strings filtered",
			ips:         []string{"8.8.8.8", "", "  ", "1.1.1.1"},
			wantValid:   2,
			wantInvalid: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, errs := c.validateIPs(tt.ips)
			if len(valid) != tt.wantValid {
				t.Errorf("expected %d valid, got %d", tt.wantValid, len(valid))
			}
			if len(errs) != tt.wantInvalid {
				t.Errorf("expected %d invalid, got %d", tt.wantInvalid, len(errs))
			}
		})
	}
}

func TestBuildRequest(t *testing.T) {
	c := NewClient()
	ips := []string{"8.8.8.8", "1.1.1.1"}
	request := c.buildRequest(ips)

	expected := "begin\nprefix\ncountrycode\n8.8.8.8\n1.1.1.1\nend\n"
	if string(request) != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, string(request))
	}
}

func TestLookupEmptyList(t *testing.T) {
	c := NewClient()
	resp, err := c.Lookup(context.Background(), []string{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(resp.Results))
	}
	if len(resp.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(resp.Errors))
	}
}

func TestLookupAllInvalid(t *testing.T) {
	c := NewClient()
	resp, err := c.Lookup(context.Background(), []string{"not-an-ip", "also-invalid"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(resp.Results))
	}
	if len(resp.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(resp.Errors))
	}
}

func TestLookupWithMockServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Logf("failed to close listener: %v", closeErr)
		}
	}()

	mockResponse := `Bulk mode; whois.cymru.com [2024-01-15 12:00:00 +0000]
15169   | 8.8.8.8          | 8.8.8.0/24       | US | GOOGLE, US
13335   | 1.1.1.1          | 1.1.1.0/24       | US | CLOUDFLARE, US
`

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("failed to close connection: %v", closeErr)
			}
		}()

		buf := make([]byte, 1024)
		_, readErr := conn.Read(buf)
		if readErr != nil {
			return
		}

		_, writeErr := conn.Write([]byte(mockResponse))
		if writeErr != nil {
			return
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	c := NewClient(
		WithServer("127.0.0.1"),
		WithPort(fmt.Sprintf("%d", addr.Port)),
		WithTimeout(5*time.Second),
	)

	resp, err := c.Lookup(context.Background(), []string{"8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}

	if len(resp.Results) > 0 && resp.Results[0].ASN != 15169 {
		t.Errorf("expected ASN 15169, got %d", resp.Results[0].ASN)
	}
}

func TestLookupContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Logf("failed to close listener: %v", closeErr)
		}
	}()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("failed to close connection: %v", closeErr)
			}
		}()

		time.Sleep(5 * time.Second)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	c := NewClient(
		WithServer("127.0.0.1"),
		WithPort(fmt.Sprintf("%d", addr.Port)),
		WithTimeout(10*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = c.Lookup(ctx, []string{"8.8.8.8"})
	if err == nil {
		t.Error("expected error due to context timeout, got nil")
	}
}

func TestLookupConnectionFailure(t *testing.T) {
	c := NewClient(
		WithServer("127.0.0.1"),
		WithPort("59999"),
		WithTimeout(1*time.Second),
	)

	_, err := c.Lookup(context.Background(), []string{"8.8.8.8"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
