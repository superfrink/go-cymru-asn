# go-cymru-asn

A Go library and CLI tool for fetching Autonomous System Numbers (ASNs) and BGP information for IP addresses using [Team Cymru's IP-to-ASN mapping service](https://www.team-cymru.com/ip-asn-mapping).

**Note:** This library uses Team Cymru's netcat interface, which is designed for bulk querying of multiple IP addresses. It is not intended for querying individual IP addresses. For single IP lookups use their DNS interface instead.

## Installation

```bash
go install github.com/superfrink/go-cymru-asn/cmd/go-cymru-asn@latest
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    asn "github.com/superfrink/go-cymru-asn"
)

func main() {
    client := asn.NewClient(
        asn.WithTimeout(30 * time.Second),
    )

    ips := []string{"8.8.8.8", "1.1.1.1", "208.67.222.222"}

    resp, err := client.Lookup(context.Background(), ips)
    if err != nil {
        log.Fatal(err)
    }

    for _, r := range resp.Results {
        fmt.Printf("IP: %s, ASN: %d, Name: %s\n", r.IP, r.ASN, r.ASName)
    }

    for _, e := range resp.Errors {
        fmt.Printf("Error for %s: %v\n", e.IP, e.Err)
    }
}
```

## CLI Usage

```bash
# Single IP
go-cymru-asn 8.8.8.8

# Multiple IPs
go-cymru-asn 8.8.8.8 1.1.1.1 208.67.222.222

# From stdin
echo -e "8.8.8.8\n1.1.1.1" | go-cymru-asn

# With options
go-cymru-asn -timeout 60s 8.8.8.8
```

## OpenBSD pledge(2) Requirements

When running on OpenBSD with pledge(2) restrictions, the CLI tool requires:

- `stdio` — standard I/O operations
- `inet` — network access (TCP connection to whois server)
- `dns` — DNS resolution (for resolving `whois.cymru.com`)

## Testing

```bash
# Run unit tests
go test ./...

# Run integration tests (requires network access)
go test -tags=integration ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure tests pass: `go test ./...`
4. Ensure code is clean: `go vet ./...`
5. Submit a pull request

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
