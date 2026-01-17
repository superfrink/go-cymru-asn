package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	cymruasn "github.com/superfrink/go-cymru-asn"
)

func main() {
	sandbox()

	timeout := flag.Duration("timeout", 30*time.Second, "connection timeout")
	server := flag.String("server", cymruasn.DefaultServer, "whois server address")
	flag.Parse()

	ips := flag.Args()

	if len(ips) == 0 {
		ips = readFromStdin()
	}

	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "usage: go-cymru-asn [-timeout duration] [-server addr] IP [IP ...]")
		fmt.Fprintln(os.Stderr, "       or pipe IPs via stdin (one per line)")
		os.Exit(2)
	}

	client := cymruasn.NewClient(
		cymruasn.WithTimeout(*timeout),
		cymruasn.WithServer(*server),
	)

	resp, err := client.Lookup(context.Background(), ips)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	for _, r := range resp.Results {
		fmt.Printf("%s\t%d\t%s\t%s\t%s\n", r.IP, r.ASN, r.BGPPrefix, r.CountryCode, r.ASName)
	}

	for _, e := range resp.Errors {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", e.IP, e.Err)
	}

	if len(resp.Errors) > 0 && len(resp.Results) > 0 {
		os.Exit(1)
	}

	if len(resp.Errors) > 0 && len(resp.Results) == 0 {
		os.Exit(2)
	}
}

func readFromStdin() []string {
	var ips []string

	info, err := os.Stdin.Stat()
	if err != nil {
		return ips
	}

	if info.Mode()&os.ModeCharDevice != 0 {
		return ips
	}

	const maxLineSize = 1024 * 1024 // 1MB max line size
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			fmt.Fprintf(os.Stderr, "error reading stdin: line exceeded maximum length of %d bytes\n", maxLineSize)
		} else {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		}
	}

	return ips
}
