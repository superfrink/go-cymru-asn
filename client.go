package cymruasn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// NewClient creates a new ASN lookup client with the given options.
func NewClient(opts ...Option) *Client {
	c := &Client{
		server:  DefaultServer,
		port:    DefaultPort,
		timeout: DefaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Lookup performs a bulk ASN lookup for the given IP addresses.
// It returns a Response containing successful results and any lookup errors.
// The function returns a non-nil error only for connection-level failures.
func (c *Client) Lookup(ctx context.Context, ips []string) (*Response, error) {
	if len(ips) == 0 {
		return &Response{}, nil
	}

	validIPs, invalidErrs := c.validateIPs(ips)

	if len(validIPs) == 0 {
		return &Response{Errors: invalidErrs}, nil
	}

	request := c.buildRequest(validIPs)

	results, parseErrs, err := c.query(ctx, request)
	if err != nil {
		return nil, err
	}

	lookupErrs := c.matchResultsToIPs(validIPs, results)
	allErrors := append(invalidErrs, lookupErrs...)

	return &Response{
		Results:     results,
		Errors:      allErrors,
		ParseErrors: parseErrs,
	}, nil
}

// validateIPs checks each IP and returns valid IPs and errors for invalid ones.
func (c *Client) validateIPs(ips []string) ([]string, []LookupError) {
	var valid []string
	var errs []LookupError

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		if !isValidIP(ip) {
			errs = append(errs, LookupError{
				IP:  ip,
				Err: fmt.Errorf("invalid IP address: %s", ip),
			})
			continue
		}

		valid = append(valid, ip)
	}

	return valid, errs
}

// isValidIP checks if the string is a valid IPv4 or IPv6 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// buildRequest creates the bulk whois request payload.
func (c *Client) buildRequest(ips []string) []byte {
	var buf bytes.Buffer

	buf.WriteString("begin\n")
	buf.WriteString("prefix\n")
	buf.WriteString("countrycode\n")

	for _, ip := range ips {
		buf.WriteString(ip)
		buf.WriteString("\n")
	}

	buf.WriteString("end\n")

	return buf.Bytes()
}

// MaxResponseSize is the maximum allowed response size (10MB).
const MaxResponseSize = 10 * 1024 * 1024

// query sends the request to the whois server and returns parsed results.
func (c *Client) query(ctx context.Context, request []byte) ([]Result, []ParseError, error) {
	addr := net.JoinHostPort(c.server, c.port)

	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	if setErr := conn.SetDeadline(deadline); setErr != nil {
		return nil, nil, fmt.Errorf("failed to set deadline: %w", setErr)
	}

	_, err = conn.Write(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}

	limitedReader := io.LimitReader(conn, MaxResponseSize+1)
	response, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}
	if len(response) > MaxResponseSize {
		return nil, nil, fmt.Errorf("response exceeded maximum size of %d bytes", MaxResponseSize)
	}

	return parseResponse(response)
}

// matchResultsToIPs checks which requested IPs are missing from results.
func (c *Client) matchResultsToIPs(requestedIPs []string, results []Result) []LookupError {
	resultMap := make(map[string]bool)
	for _, r := range results {
		resultMap[r.IP] = true
	}

	var errs []LookupError
	for _, ip := range requestedIPs {
		if !resultMap[ip] {
			errs = append(errs, LookupError{
				IP:  ip,
				Err: fmt.Errorf("no result returned for IP: %s", ip),
			})
		}
	}

	return errs
}
