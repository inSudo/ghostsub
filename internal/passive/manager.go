package passive

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ghostsub/internal/config"
	"github.com/ghostsub/internal/passive/sources"
)

// Manager fans out to all passive sources concurrently.
type Manager struct {
	sources    []Source
	cfg        *config.Config
	verbose    bool
	sourceTime map[string]time.Duration // tracks how long each source took
	mu         sync.Mutex
}

// NewManager creates a Manager with all sources wired up.
func NewManager(cfg *config.Config) *Manager {
	m := &Manager{
		cfg:        cfg,
		verbose:    cfg.Verbose,
		sourceTime: make(map[string]time.Duration),
	}

	// Build source list based on config
	all := m.buildSources(cfg)

	// Filter: include/exclude based on config
	include := make(map[string]bool)
	exclude := make(map[string]bool)

	for _, s := range cfg.Sources {
		include[strings.ToLower(s)] = true
	}
	for _, s := range cfg.ExcludeSources {
		exclude[strings.ToLower(s)] = true
	}

	for _, src := range all {
		name := strings.ToLower(src.Name())

		// Skip if excluded
		if exclude[name] {
			continue
		}

		// If include list specified, only use those
		if len(include) > 0 && !include[name] {
			continue
		}

		// Skip key-required sources if no key provided
		if src.NeedsKey() && !cfg.HasKey(name) {
			continue
		}

		m.sources = append(m.sources, src)
	}

	return m
}

func (m *Manager) buildSources(cfg *config.Config) []Source {
	return []Source{
		// No-key sources
		sources.NewCrtSh(),
		sources.NewHackerTarget(),
		sources.NewAlienVault(),
		sources.NewURLScan(),
		sources.NewWayback(),
		sources.NewThreatMiner(),
		sources.NewAnubis(),
		sources.NewCertSpotter(),
		sources.NewRapidDNS(),
		sources.NewSubdomainCenter(),
		sources.NewBufferOver(),
		sources.NewLeakIX(),
		sources.NewCommonCrawl(),
		sources.NewDNSRepo(),
		sources.NewSiteDossier(),
		sources.NewDNSDumpster(),
		sources.NewRiddler(),
		sources.NewViewDNS(),
		sources.NewWebarchive(),
		sources.NewSonarSearch(),
		sources.NewGitHub(cfg.GetKey("github")),

		// Optional key sources
		sources.NewVirusTotal(cfg.GetKey("virustotal")),
		sources.NewSecurityTrails(cfg.GetKey("securitytrails")),
		sources.NewFullHunt(cfg.GetKey("fullhunt")),
		sources.NewBevigil(cfg.GetKey("bevigil")),
		sources.NewNetlas(cfg.GetKey("netlas")),
		sources.NewShodan(cfg.GetKey("shodan")),
		sources.NewBinaryEdge(cfg.GetKey("binaryedge")),
		sources.NewChaos(cfg.GetKey("chaos")),
		sources.NewFOFA(cfg.GetKey("fofa_email"), cfg.GetKey("fofa")),
		sources.NewPassiveTotal(cfg.GetKey("passivetotal_user"), cfg.GetKey("passivetotal")),
	}
}

// Run fans out queries to all sources concurrently.
// Returns a channel of deduplicated subdomain strings.
func (m *Manager) Run(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 2000)

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		// Semaphore: max 15 sources at once (avoid too many concurrent HTTP connections)
		sem := make(chan struct{}, 15)

		for _, src := range m.sources {
			wg.Add(1)
			go func(s Source) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				start := time.Now()
				name := s.Name()

				// Per-source timeout: don't let one slow source block others
				srcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()

				defer func() {
					elapsed := time.Since(start)
					m.mu.Lock()
					m.sourceTime[name] = elapsed
					m.mu.Unlock()
				}()

				if m.verbose {
					fmt.Printf("\r[passive] querying %s...\n", name)
				}

				ch := s.Query(srcCtx, domain)
				count := 0

				for {
					select {
					case sub, ok := <-ch:
						if !ok {
							if m.verbose && count > 0 {
								fmt.Printf("[passive] %s → %d results\n", name, count)
							}
							return
						}
						count++
						select {
						case out <- sub:
						case <-ctx.Done():
							return
						}
					case <-ctx.Done():
						return
					}
				}
			}(src)
		}

		wg.Wait()
	}()

	return out
}

// ActiveSources returns the names of all active sources.
func (m *Manager) ActiveSources() []string {
	names := make([]string, 0, len(m.sources))
	for _, s := range m.sources {
		names = append(names, s.Name())
	}
	return names
}

// SourceStats returns timing stats per source.
func (m *Manager) SourceStats() map[string]time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]time.Duration, len(m.sourceTime))
	for k, v := range m.sourceTime {
		out[k] = v
	}
	return out
}
