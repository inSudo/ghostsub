package resolver

import (
	"math/rand"
	"sync"
	"time"
)

// Default public DNS resolvers — large pool for distribution.
var defaultResolvers = []string{
	// Google
	"8.8.8.8:53", "8.8.4.4:53",
	// Cloudflare
	"1.1.1.1:53", "1.0.0.1:53",
	// Quad9
	"9.9.9.9:53", "149.112.112.112:53",
	// OpenDNS
	"208.67.222.222:53", "208.67.220.220:53",
	// Level3 / Lumen
	"4.2.2.1:53", "4.2.2.2:53", "4.2.2.3:53", "4.2.2.4:53", "4.2.2.5:53", "4.2.2.6:53",
	// Comodo Secure DNS
	"8.26.56.26:53", "8.20.247.20:53",
	// Verisign
	"64.6.64.6:53", "64.6.65.6:53",
	// Freenom DNS
	"80.80.80.80:53", "80.80.81.81:53",
	// AdGuard DNS
	"94.140.14.14:53", "94.140.15.15:53",
	// CleanBrowsing
	"185.228.168.9:53", "185.228.169.9:53",
	// Alternate DNS
	"76.76.19.19:53", "76.223.122.150:53",
	// Hurricane Electric
	"74.82.42.42:53",
	// Yandex DNS
	"77.88.8.8:53", "77.88.8.1:53",
	// Neustar UltraDNS
	"156.154.70.1:53", "156.154.71.1:53",
	// Dyn DNS
	"216.146.35.35:53", "216.146.36.36:53",
	// SafeDNS
	"195.46.39.39:53", "195.46.39.40:53",
	// DNS.Watch
	"84.200.69.80:53", "84.200.70.40:53",
	// puntCAT
	"109.69.8.51:53",
	// Chaos Computer Club
	"87.118.111.215:53", "87.118.100.175:53",
	// UncensoredDNS
	"91.239.100.100:53", "89.233.43.71:53",
	// SkyDNS
	"193.58.251.251:53",
	// SmartViper
	"208.76.50.50:53", "208.76.51.51:53",
	// Linode (various)
	"45.33.97.5:53", "45.79.19.196:53",
	// OpenNIC nodes (global)
	"69.195.152.204:53",
	"193.183.98.154:53",
	"178.63.116.152:53",
	"176.9.93.198:53", "176.9.1.117:53",
	"185.43.135.1:53",
	"81.218.119.11:53",
	"209.88.198.133:53",
	"75.127.14.165:53",
	"5.9.49.12:53", "5.9.54.33:53",
	"136.243.151.101:53",
	// Digitalcourage (Germany)
	"46.182.19.48:53",
	// FDN (France)
	"80.67.169.12:53",
	// LavaBit
	"66.175.214.2:53",
	// Censurfridns (Denmark)
	"91.239.100.100:53",
	// DNS for Family
	"94.130.180.225:53", "78.47.64.161:53",
	// NextDNS
	"45.90.28.0:53", "45.90.30.0:53",
	// ControlD
	"76.76.2.0:53", "76.76.10.0:53",
	// Mullvad DNS
	"194.242.2.2:53", "194.242.2.3:53",
	// SWITCH DNS (Switzerland)
	"130.59.31.248:53", "130.59.31.251:53",
	// Surfnet (Netherlands)
	"195.169.124.10:53",
	// Tele2 (Sweden)
	"195.54.12.215:53",
	// T-Systems (Germany)
	"194.25.0.60:53",
	// Various global open resolvers
	"198.101.242.72:53",
	"23.253.163.53:53",
	"37.235.1.174:53", "37.235.1.177:53",
	"91.108.4.1:53",
	"103.86.96.100:53", "103.86.99.100:53",
}

// healthEntry tracks per-resolver health.
type healthEntry struct {
	failures    int
	blacklisted bool
	blackUntil  time.Time
}

// Pool manages a rotating pool of DNS resolvers with health tracking.
type Pool struct {
	resolvers []string
	trusted   []string
	health    map[string]*healthEntry
	mu        sync.RWMutex
	idx       int
}

// NewPool creates a Pool. If resolvers is empty, uses defaults.
func NewPool(resolvers, trusted []string) *Pool {
	if len(resolvers) == 0 {
		resolvers = defaultResolvers
	}
	if len(trusted) == 0 {
		trusted = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	}

	health := make(map[string]*healthEntry)
	for _, r := range resolvers {
		health[r] = &healthEntry{}
	}

	return &Pool{
		resolvers: resolvers,
		trusted:   trusted,
		health:    health,
	}
}

// Pick returns a healthy resolver (round-robin with blacklist skip).
func (p *Pool) Pick() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	tried := 0
	for tried < len(p.resolvers) {
		p.idx = (p.idx + 1) % len(p.resolvers)
		r := p.resolvers[p.idx]
		h := p.health[r]

		// Re-enable after blacklist window expires
		if h.blacklisted && time.Now().After(h.blackUntil) {
			h.blacklisted = false
			h.failures = 0
		}

		if !h.blacklisted {
			return r
		}
		tried++
	}

	// All blacklisted — return random trusted resolver
	return p.trusted[rand.Intn(len(p.trusted))]
}

// PickTrusted returns a trusted resolver.
func (p *Pool) PickTrusted() string {
	return p.trusted[rand.Intn(len(p.trusted))]
}

// MarkFailure records a failure for a resolver.
// After 5 failures, resolver is blacklisted for 60 seconds.
func (p *Pool) MarkFailure(resolver string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	h, ok := p.health[resolver]
	if !ok {
		return
	}

	h.failures++
	if h.failures >= 5 {
		h.blacklisted = true
		h.blackUntil = time.Now().Add(60 * time.Second)
		h.failures = 0
	}
}

// MarkSuccess resets failure count for a resolver.
func (p *Pool) MarkSuccess(resolver string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if h, ok := p.health[resolver]; ok {
		h.failures = 0
		h.blacklisted = false
	}
}

// HealthyCount returns number of non-blacklisted resolvers.
func (p *Pool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, h := range p.health {
		if !h.blacklisted {
			count++
		}
	}
	return count
}

// Trusted returns the trusted resolver list.
func (p *Pool) Trusted() []string {
	return p.trusted
}
