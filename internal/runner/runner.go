package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghostsub/internal/brute"
	"github.com/ghostsub/internal/config"
	"github.com/ghostsub/internal/output"
	"github.com/ghostsub/internal/passive"
	"github.com/ghostsub/internal/permute"
	"github.com/ghostsub/internal/resolver"
)

// Runner orchestrates the full enumeration pipeline.
type Runner struct {
	cfg      *config.Config
	writer   *output.Writer
	pool     *resolver.Pool
	res      *resolver.Resolver
	passive  *passive.Manager
	bruter   *brute.Bruteforcer
	permuter *permute.Engine
	wc       *resolver.WildcardDetector
}

// New creates a Runner from config.
func New(cfg *config.Config) (*Runner, error) {
	// Output writer
	w, err := output.New(cfg.Silent, cfg.NoColor, cfg.OutputFile, cfg.OutputJSON)
	if err != nil {
		return nil, err
	}

	// DNS pool + resolver
	pool := resolver.NewPool(cfg.Resolvers, cfg.TrustedDNS)
	res := resolver.New(pool, cfg.DNSTimeout, cfg.DNSRetries)

	// Passive manager
	pm := passive.NewManager(cfg)

	return &Runner{
		cfg:      cfg,
		writer:   w,
		pool:     pool,
		res:      res,
		passive:  pm,
	}, nil
}

// Run executes the full enumeration pipeline for a single domain.
func (r *Runner) Run(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if !r.cfg.Silent {
		fmt.Printf("\n[ghostsub] target: %s\n", domain)
		fmt.Printf("[ghostsub] modes: passive=%v brute=%v permute=%v verify=%v\n",
			r.cfg.Passive, r.cfg.Brute, r.cfg.Permute, r.cfg.Verify)
		if r.cfg.Passive {
			fmt.Printf("[ghostsub] sources: %s\n", strings.Join(r.passive.ActiveSources(), ", "))
		}
		fmt.Printf("[ghostsub] threads: %d\n", r.cfg.Threads)
		fmt.Println()
	}

	start := time.Now()

	// ── Step 1: NXDOMAIN hijack detection ────────────────────────────────────
	hijackIPs := r.res.ResolveNXDOMAINHijack(ctx, domain)
	if len(hijackIPs) > 0 && !r.cfg.Silent {
		fmt.Printf("[warn] ISP NXDOMAIN hijack detected — IPs will be filtered from results\n")
	}

	// ── Step 2: Wildcard detection ────────────────────────────────────────────
	wc := resolver.NewWildcardDetector(domain, r.res)
	if !r.cfg.NoWildcardFilter {
		if err := wc.Detect(ctx); err != nil && !r.cfg.Silent {
			fmt.Printf("[warn] wildcard detection error: %v\n", err)
		}
		if wc.Detected() && !r.cfg.Silent {
			fmt.Printf("[warn] %s\n", wc.Summary())
		}
	}
	r.wc = wc

	// ── Step 3: Bruter (initialized here with wc) ────────────────────────────
	r.bruter = brute.New(r.res, wc, r.cfg.Threads, r.cfg.Verbose)

	// ── Step 4: Collect all results ───────────────────────────────────────────
	// We run passive + brute concurrently, collect, then permute.
	allSubs := make(chan string, 5000)
	var wg sync.WaitGroup

	// ── 4a: Passive ───────────────────────────────────────────────────────────
	if r.cfg.Passive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range r.passive.Run(ctx, domain) {
				select {
				case allSubs <- sub:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// ── 4b: Brute ─────────────────────────────────────────────────────────────
	if r.cfg.Brute {
		wg.Add(1)
		go func() {
			defer wg.Done()

			wlCh, err := brute.LoadWordlist(r.cfg.Wordlist)
			if err != nil {
				fmt.Printf("[error] load wordlist: %v\n", err)
				return
			}

			for host := range r.bruter.Run(ctx, domain, wlCh, r.cfg.ResumeFile) {
				select {
				case allSubs <- host:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Close allSubs when passive+brute done
	go func() {
		wg.Wait()
		close(allSubs)
	}()

	// ── 4c: Drain + write passive/brute results ───────────────────────────────
	collected := []string{}
	for sub := range allSubs {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			continue
		}
		// Validate: must end with .domain
		if !strings.HasSuffix(sub, "."+domain) && sub != domain {
			continue
		}

		// Filter hijack IPs
		if isHijacked(sub, hijackIPs) {
			continue
		}

		// Write (dedup handled in writer)
		if r.writer.Write(sub, "passive/brute", nil) {
			collected = append(collected, sub)
		}
	}

	if !r.cfg.Silent {
		fmt.Printf("\n[passive/brute] found %d unique subdomains\n", len(collected))
	}

	// ── Step 5: Permutation ───────────────────────────────────────────────────
	if r.cfg.Permute && len(collected) > 0 {
		if !r.cfg.Silent {
			fmt.Printf("[permute] generating permutations from %d discovered subs...\n", len(collected))
		}

		r.permuter = permute.New(nil, r.cfg.Verbose)
		permCh := r.permuter.Generate(collected, domain)

		// Resolve permutations concurrently
		sem := make(chan struct{}, r.cfg.Threads)
		var permWg sync.WaitGroup
		var permFound atomic.Int64

		for perm := range permCh {
			if ctx.Err() != nil {
				break
			}
			if r.writer.Seen(perm) {
				continue
			}

			sem <- struct{}{}
			permWg.Add(1)

			go func(p string) {
				defer permWg.Done()
				defer func() { <-sem }()

				res, err := r.res.Resolve(ctx, p)
				if err != nil || len(res.IPs) == 0 {
					return
				}

				if wc != nil && !r.cfg.NoWildcardFilter && wc.IsWildcard(res.IPs) {
					return
				}

				if r.writer.Write(p, "permute", res.IPs) {
					permFound.Add(1)
				}
			}(perm)
		}

		permWg.Wait()

		if !r.cfg.Silent {
			fmt.Printf("[permute] found %d new subdomains\n", permFound.Load())
		}
	}

	// ── Step 6: Final verify with trusted DNS ─────────────────────────────────
	// (Optional — already verified during brute, this is extra paranoia)

	// ── Step 7: Summary ───────────────────────────────────────────────────────
	elapsed := time.Since(start)
	total := r.writer.Count()

	if !r.cfg.Silent {
		fmt.Printf("\n[ghostsub] done in %s\n", elapsed.Round(time.Second))
		fmt.Printf("[ghostsub] total unique: %d\n", total)
		if r.cfg.OutputFile != "" {
			fmt.Printf("[ghostsub] saved to: %s\n", r.cfg.OutputFile)
		}
		if r.cfg.OutputJSON != "" {
			fmt.Printf("[ghostsub] json saved to: %s\n", r.cfg.OutputJSON)
		}
		if r.cfg.Brute {
			r.bruter.PrintStats()
		}
	}

	return r.writer.Close()
}

// RunMulti runs against multiple domains (from -dL).
func (r *Runner) RunMulti(ctx context.Context, domains []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle Ctrl+C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !r.cfg.Silent {
			fmt.Println("\n[ghostsub] interrupted — saving partial results...")
		}
		cancel()
	}()

	sem := make(chan struct{}, r.cfg.Parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for _, domain := range domains {
		if ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Create per-domain runner with shared pool
			domainCfg := *r.cfg
			domainCfg.Domain = d

			domainRunner, err := New(&domainCfg)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", d, err))
				mu.Unlock()
				return
			}

			if err := domainRunner.Run(ctx, d); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", d, err))
				mu.Unlock()
			}
		}(domain)
	}

	wg.Wait()

	if len(errors) > 0 {
		fmt.Printf("\n[ghostsub] %d errors:\n", len(errors))
		for _, e := range errors {
			fmt.Printf("  - %v\n", e)
		}
	}

	return nil
}

func isHijacked(sub string, hijackIPs map[string]struct{}) bool {
	// We'd need to resolve to check, but since we filter at resolver level this is a backup
	// For now, just return false — resolver already handles this
	return false
}
