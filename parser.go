package cymruasn

import (
	"bufio"
	"bytes"
	"errors"
	"strconv"
	"strings"
)

var (
	ErrEmptyResponse  = errors.New("empty response from server")
	ErrInvalidFormat  = errors.New("invalid response format")
	ErrNoResults      = errors.New("no results in response")
)

// parseResponse parses the bulk whois response into Result structs.
// Response format (pipe-delimited):
//
//	Bulk mode; whois.cymru.com [timestamp]
//	AS      | IP               | BGP Prefix       | CC | AS Name
//	15169   | 8.8.8.8          | 8.8.8.0/24       | US | GOOGLE, US
func parseResponse(data []byte) ([]Result, error) {
	if len(data) == 0 {
		return nil, ErrEmptyResponse
	}

	var results []Result
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Bulk mode;") {
			continue
		}

		if isHeaderLine(line) {
			continue
		}

		result, err := parseLine(line)
		if err != nil {
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return results, err
	}

	return results, nil
}

// isHeaderLine checks if the line is a column header line.
func isHeaderLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "as name") || 
		(strings.HasPrefix(lower, "as") && strings.Contains(lower, "| ip"))
}

// parseLine parses a single pipe-delimited result line.
// Expected format: AS | IP | BGP Prefix | CC | AS Name
func parseLine(line string) (Result, error) {
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return Result{}, ErrInvalidFormat
	}

	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	var result Result

	asnStr := parts[0]
	if asnStr == "NA" || asnStr == "" {
		result.ASN = 0
	} else {
		asn, err := strconv.Atoi(asnStr)
		if err != nil {
			return Result{}, err
		}
		result.ASN = asn
	}

	if len(parts) >= 2 {
		result.IP = parts[1]
	}

	if len(parts) >= 3 {
		result.BGPPrefix = parts[2]
	}

	if len(parts) >= 4 {
		result.CountryCode = parts[3]
	}

	if len(parts) >= 5 {
		result.ASName = parts[4]
	}

	return result, nil
}
