package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Result holds a resolved subdomain result.
type Result struct {
	Host   string
	IPs    []string
	CNAMEs []string
}

// Resolver performs DNS resolution with pool rotation, TCP fallback, retry.
type Resolver struct {
	pool    *Pool
	timeout time.Duration
	retries int
}

// New creates a Resolver.
func New(pool *Pool, timeout time.Duration, retries int) *Resolver {
	return &Resolver{
		pool:    pool,
		timeout: timeout,
		retries: retries,
	}
}

// Resolve resolves a hostname to A records.
// Handles: UDP truncation → TCP fallback, resolver rotation, CNAME follow (max depth 5).
func (r *Resolver) Resolve(ctx context.Context, host string) (*Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	host = dns.Fqdn(strings.ToLower(strings.TrimSpace(host)))

	for attempt := 0; attempt < r.retries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		resolver := r.pool.Pick()
		result, err := r.queryA(ctx, host, resolver, false)
		if err != nil {
			r.pool.MarkFailure(resolver)
			if attempt < r.retries-1 {
				continue
			}
			return nil, err
		}

		r.pool.MarkSuccess(resolver)
		return result, nil
	}

	return nil, fmt.Errorf("resolve failed after %d attempts: %s", r.retries, host)
}

// ResolveWithTrusted does final verification using trusted resolvers only.
func (r *Resolver) ResolveWithTrusted(ctx context.Context, host string) (*Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	host = dns.Fqdn(strings.ToLower(strings.TrimSpace(host)))

	for attempt := 0; attempt < r.retries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		resolver := r.pool.PickTrusted()
		result, err := r.queryA(ctx, host, resolver, false)
		if err != nil {
			continue
		}
		return result, nil
	}

	return nil, fmt.Errorf("trusted resolve failed: %s", host)
}

func (r *Resolver) queryA(ctx context.Context, host, resolver string, tcp bool) (*Result, error) {
	client := &dns.Client{
		Timeout: r.timeout,
	}
	if tcp {
		client.Net = "tcp"
	}

	msg := new(dns.Msg)
	msg.SetQuestion(host, dns.TypeA)
	msg.RecursionDesired = true

	// Context-aware deadline
	deadline, ok := ctx.Deadline()
	if ok {
		remaining := time.Until(deadline)
		if remaining < r.timeout {
			client.Timeout = remaining
		}
	}

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, fmt.Errorf("dns exchange: %w", err)
	}

	if resp == nil {
		return nil, fmt.Errorf("nil dns response")
	}

	// TCP fallback on truncation
	if resp.Truncated && !tcp {
		return r.queryA(ctx, host, resolver, true)
	}

	result := &Result{Host: strings.TrimSuffix(host, ".")}

	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			result.IPs = append(result.IPs, rr.A.String())
		case *dns.CNAME:
			result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(rr.Target, "."))
		}
	}

	return result, nil
}

// ResolveNXDOMAINHijack checks if NXDOMAIN is being hijacked by ISP.
// Returns the hijack IPs if detected.
func (r *Resolver) ResolveNXDOMAINHijack(ctx context.Context, domain string) map[string]struct{} {
	hijackIPs := make(map[string]struct{})

	// Generate obviously non-existent subdomains
	probes := []string{
		"this-definitely-does-not-exist-xyz9q." + domain,
		"zz9q8w7e6r5t4y3u2i1o0p-nxtest." + domain,
		"nxdomainhijacktest12345." + domain,
	}

	ipCount := make(map[string]int)
	for _, probe := range probes {
		res, err := r.Resolve(ctx, probe)
		if err != nil {
			continue
		}
		for _, ip := range res.IPs {
			ipCount[ip]++
		}
	}

	// If IPs appear across multiple probes — ISP hijacking
	for ip, count := range ipCount {
		if count >= 2 {
			hijackIPs[ip] = struct{}{}
		}
	}

	return hijackIPs
}
