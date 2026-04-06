package brute

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghostsub/internal/resolver"
)

// Checkpoint holds resume state for interrupted brute-force.
type Checkpoint struct {
	Domain    string   `json:"domain"`
	Wordlist  string   `json:"wordlist"`
	Done      []string `json:"done"`
	Found     []string `json:"found"`
	Timestamp string   `json:"timestamp"`
}

// Stats holds real-time bruteforce statistics.
type Stats struct {
	Tried    atomic.Int64
	Found    atomic.Int64
	Errors   atomic.Int64
	Filtered atomic.Int64 // wildcard filtered
}

// Bruteforcer performs concurrent DNS brute-force with smart features.
type Bruteforcer struct {
	res            *resolver.Resolver
	wc             *resolver.WildcardDetector
	threads        int
	verbose        bool
	Stats          *Stats
	currentThreads atomic.Int64
}

// New creates a Bruteforcer.
func New(res *resolver.Resolver, wc *resolver.WildcardDetector, threads int, verbose bool) *Bruteforcer {
	b := &Bruteforcer{
		res:     res,
		wc:      wc,
		threads: threads,
		verbose: verbose,
		Stats:   &Stats{},
	}
	b.currentThreads.Store(int64(threads))
	return b
}

// Run streams resolved subdomains for the given domain.
func (b *Bruteforcer) Run(ctx context.Context, domain string, wordlistCh <-chan string, resumeFile string) <-chan string {
	out := make(chan string, 500)

	go func() {
		defer close(out)

		_, doneSet := b.loadCheckpoint(resumeFile, domain)

		throttleTicker := time.NewTicker(10 * time.Second)
		defer throttleTicker.Stop()

		sem := make(chan struct{}, b.threads)
		var wg sync.WaitGroup

		// Adaptive throttle goroutine — uses atomic to avoid data race
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-throttleTicker.C:
					tried := b.Stats.Tried.Load()
					errs := b.Stats.Errors.Load()
					if tried < 200 {
						continue
					}
					rate := float64(errs) / float64(tried)
					cur := b.currentThreads.Load()
					if rate > 0.35 && cur > 20 {
						newT := cur / 2
						b.currentThreads.Store(newT)
						if b.verbose {
							fmt.Printf("\r[brute] high error rate (%.0f%%), threads→%d\n", rate*100, newT)
						}
					} else if rate < 0.05 && cur < int64(b.threads) {
						newT := cur + 20
						if newT > int64(b.threads) {
							newT = int64(b.threads)
						}
						b.currentThreads.Store(newT)
						if b.verbose {
							fmt.Printf("\r[brute] network stable, threads→%d\n", newT)
						}
					}
				}
			}
		}()

		for word := range wordlistCh {
			if ctx.Err() != nil {
				break
			}
			if doneSet[word] {
				continue
			}

			// Drain excess slots if threads were reduced
			cur := int(b.currentThreads.Load())
			for len(sem) >= cur && cur > 0 {
				select {
				case <-ctx.Done():
					wg.Wait()
					return
				case <-time.After(5 * time.Millisecond):
					cur = int(b.currentThreads.Load())
				}
			}

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break
			}

			wg.Add(1)
			go func(w string) {
				defer wg.Done()
				defer func() { <-sem }()

				host := w + "." + domain
				b.Stats.Tried.Add(1)

				res, err := b.res.Resolve(ctx, host)
				if err != nil {
					b.Stats.Errors.Add(1)
					return
				}
				if res == nil || len(res.IPs) == 0 {
					return
				}
				if b.wc != nil && b.wc.IsWildcard(res.IPs) {
					b.Stats.Filtered.Add(1)
					return
				}

				b.Stats.Found.Add(1)
				select {
				case out <- host:
				case <-ctx.Done():
				}
			}(word)
		}

		wg.Wait()
	}()

	return out
}

// RunRecursive brute-forces sub-levels of discovered subdomains.
func (b *Bruteforcer) RunRecursive(ctx context.Context, discovered []string, domain string, wordlistPath string, depth int) <-chan string {
	out := make(chan string, 500)

	if depth <= 0 {
		close(out)
		return out
	}

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		for _, sub := range discovered {
			// Only recurse if sub is directly under domain (not already nested deep)
			parts := strings.Split(sub, ".")
			domainParts := strings.Split(domain, ".")
			if len(parts)-len(domainParts) >= depth {
				continue
			}

			wg.Add(1)
			go func(parent string) {
				defer wg.Done()

				wlCh, err := LoadWordlist(wordlistPath)
				if err != nil {
					return
				}

				for host := range b.Run(ctx, parent, wlCh, "") {
					select {
					case out <- host:
					case <-ctx.Done():
						return
					}
				}
			}(sub)
		}
		wg.Wait()
	}()

	return out
}

// SaveCheckpoint writes current progress to a checkpoint file.
func (b *Bruteforcer) SaveCheckpoint(path, domain, wordlist string, done, found []string) error {
	if path == "" {
		return nil
	}
	cp := Checkpoint{
		Domain:    domain,
		Wordlist:  wordlist,
		Done:      done,
		Found:     found,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (b *Bruteforcer) loadCheckpoint(path, domain string) (*Checkpoint, map[string]bool) {
	doneSet := make(map[string]bool)

	if path == "" {
		return nil, doneSet
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, doneSet
	}

	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, doneSet
	}

	if cp.Domain != domain {
		return nil, doneSet
	}

	for _, w := range cp.Done {
		doneSet[w] = true
	}

	return &cp, doneSet
}

// PrintStats prints current brute-force statistics.
func (b *Bruteforcer) PrintStats() {
	tried := b.Stats.Tried.Load()
	found := b.Stats.Found.Load()
	errs := b.Stats.Errors.Load()
	filtered := b.Stats.Filtered.Load()

	fmt.Printf("[brute] tried=%d found=%d errors=%d wildcard-filtered=%d\n",
		tried, found, errs, filtered)
}

// SaveResults saves found subdomains to a file, one per line.
func SaveResults(path string, subs []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, s := range subs {
		fmt.Fprintln(w, s)
	}
	return w.Flush()
}


