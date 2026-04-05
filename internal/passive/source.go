package passive

import "context"

// Source is the interface every passive enumeration source must implement.
type Source interface {
	// Name returns the unique name of this source.
	Name() string

	// Query enumerates subdomains for the given domain.
	// Results are streamed via the returned channel.
	// The channel is closed when enumeration is complete or ctx is cancelled.
	Query(ctx context.Context, domain string) <-chan string

	// NeedsKey returns true if an API key is required.
	NeedsKey() bool

	// RateLimit returns the minimum delay between requests to this source.
	RateLimit() int // requests per second, 0 = no limit
}

// Result wraps a subdomain result with source metadata.
type Result struct {
	Subdomain string
	Source    string
}
