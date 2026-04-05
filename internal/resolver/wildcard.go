package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
)

const wildcardProbes = 6
const wildcardThreshold = 3

// WildcardDetector detects and filters wildcard DNS responses.
type WildcardDetector struct {
	domain      string
	resolver    *Resolver
	wildcardIPs map[string]struct{}
	mu          sync.RWMutex
	detected    bool
}

// NewWildcardDetector creates a detector for a domain.
func NewWildcardDetector(domain string, res *Resolver) *WildcardDetector {
	return &WildcardDetector{
		domain:      domain,
		resolver:    res,
		wildcardIPs: make(map[string]struct{}),
	}
}

// Detect probes the domain with random subdomains to identify wildcard IPs.
// Must be called before filtering any results.
func (w *WildcardDetector) Detect(ctx context.Context) error {
	probes := generateRandomProbes(w.domain, wildcardProbes)

	ipFreq := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, probe := range probes {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			res, err := w.resolver.ResolveWithTrusted(ctx, p)
			if err != nil {
				return
			}
			mu.Lock()
			for _, ip := range res.IPs {
				ipFreq[ip]++
			}
			mu.Unlock()
		}(probe)
	}
	wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()

	for ip, count := range ipFreq {
		if count >= wildcardThreshold {
			w.wildcardIPs[ip] = struct{}{}
			w.detected = true
		}
	}

	return nil
}

// DetectMultiLevel also checks wildcards at sub-levels (e.g., *.internal.example.com).
func (w *WildcardDetector) DetectMultiLevel(ctx context.Context, knownSubs []string) {
	// Extract unique sub-levels
	levels := make(map[string]struct{})
	for _, sub := range knownSubs {
		// e.g., dev.internal.example.com → internal.example.com
		parts := strings.Split(sub, ".")
		if len(parts) > 2 {
			level := strings.Join(parts[1:], ".")
			// Only check levels that are sub-domains (not TLD)
			domainParts := strings.Split(w.domain, ".")
			if len(strings.Split(level, ".")) > len(domainParts) {
				levels[level] = struct{}{}
			}
		}
	}

	for level := range levels {
		probes := generateRandomProbes(level, 3)
		ipFreq := make(map[string]int)

		for _, probe := range probes {
			res, err := w.resolver.ResolveWithTrusted(ctx, probe)
			if err != nil {
				continue
			}
			for _, ip := range res.IPs {
				ipFreq[ip]++
			}
		}

		w.mu.Lock()
		for ip, count := range ipFreq {
			if count >= 2 {
				w.wildcardIPs[ip] = struct{}{}
			}
		}
		w.mu.Unlock()
	}
}

// IsWildcard returns true if the given IPs match known wildcard IPs.
func (w *WildcardDetector) IsWildcard(ips []string) bool {
	if !w.detected {
		return false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	matchCount := 0
	for _, ip := range ips {
		if _, ok := w.wildcardIPs[ip]; ok {
			matchCount++
		}
	}

	// If ALL IPs are wildcard IPs → likely wildcard
	// If only SOME match → might be legit subdomain that happens to share IP
	return matchCount > 0 && matchCount == len(ips)
}

// WildcardIPs returns the set of detected wildcard IPs (for logging/debugging).
func (w *WildcardDetector) WildcardIPs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	ips := make([]string, 0, len(w.wildcardIPs))
	for ip := range w.wildcardIPs {
		ips = append(ips, ip)
	}
	return ips
}

// Detected returns true if wildcards were found.
func (w *WildcardDetector) Detected() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.detected
}

// Summary returns a human-readable summary.
func (w *WildcardDetector) Summary() string {
	if !w.detected {
		return "no wildcard detected"
	}
	ips := w.WildcardIPs()
	return fmt.Sprintf("wildcard detected — %d IPs: %s", len(ips), strings.Join(ips, ", "))
}

func generateRandomProbes(domain string, count int) []string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	probes := make([]string, count)

	for i := 0; i < count; i++ {
		length := 12 + rand.Intn(8) // 12-20 chars
		b := make([]byte, length)
		for j := range b {
			b[j] = charset[rand.Intn(len(charset))]
		}
		probes[i] = string(b) + "." + domain
	}

	return probes
}
