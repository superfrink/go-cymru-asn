package cymruasn

import "time"

// Result contains the lookup result for a single IP address.
type Result struct {
	IP          string
	ASN         int
	BGPPrefix   string
	CountryCode string
	ASName      string
}

// LookupError represents a failed lookup for a specific IP.
type LookupError struct {
	IP  string
	Err error
}

func (e LookupError) Error() string {
	return e.Err.Error()
}

// Response contains the results of a bulk ASN lookup.
type Response struct {
	Results []Result
	Errors  []LookupError
}

// Option configures a Client.
type Option func(*Client)

// Client performs ASN lookups against Team Cymru's whois service.
type Client struct {
	server  string
	port    string
	timeout time.Duration
}

// DefaultServer is the default Team Cymru whois server.
const DefaultServer = "whois.cymru.com"

// DefaultPort is the default whois port.
const DefaultPort = "43"

// DefaultTimeout is the default connection timeout.
const DefaultTimeout = 30 * time.Second

// WithServer sets the whois server address.
func WithServer(server string) Option {
	return func(c *Client) {
		c.server = server
	}
}

// WithPort sets the whois server port.
func WithPort(port string) Option {
	return func(c *Client) {
		c.port = port
	}
}

// WithTimeout sets the connection timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.timeout = timeout
	}
}
