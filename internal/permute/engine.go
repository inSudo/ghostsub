package permute

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Common environment/service words for permutation.
var defaultWords = []string{
	// Environments
	"dev", "development", "staging", "stage", "stg", "prod", "production",
	"test", "testing", "qa", "uat", "beta", "alpha", "sandbox", "demo",
	"preview", "pre", "preprod", "hotfix", "canary", "experimental",
	// Services
	"api", "app", "web", "mobile", "admin", "portal", "dashboard",
	"auth", "sso", "login", "oauth", "identity", "account", "accounts",
	"cdn", "static", "assets", "media", "img", "images", "files",
	"mail", "smtp", "imap", "pop", "webmail", "mx",
	"vpn", "remote", "access", "gateway", "proxy", "lb",
	"git", "gitlab", "github", "ci", "cd", "jenkins", "build",
	"jira", "confluence", "wiki", "docs", "kb", "support", "help",
	"shop", "store", "pay", "payment", "billing", "checkout",
	"internal", "intranet", "private", "corp", "corporate",
	"monitor", "status", "health", "metrics", "grafana", "kibana",
	"db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
	"backup", "archive", "old", "legacy", "new", "next",
	"ws", "websocket", "socket", "stream", "events", "push",
	"search", "suggest", "recommendation",
	"data", "analytics", "report", "reports", "bi", "etl",
	"ml", "ai", "nlp", "model", "predict",
	"service", "services", "svc", "ms", "microservice",
	"v1", "v2", "v3", "v4", "v5",
	// Regions
	"us", "eu", "ap", "sg", "au", "de", "fr", "uk", "id",
	"us-east", "us-west", "eu-west", "ap-southeast",
	"east", "west", "north", "south", "central",
	// Numbers
	"0", "1", "2", "3", "4", "5",
}

// patterns defines how permutations are generated.
// Variables: {sub}, {word}, {num}, {sep}
var patterns = []string{
	"{word}-{sub}",
	"{sub}-{word}",
	"{word}.{sub}",
	"{sub}.{word}",
	"{word}{sub}",
	"{sub}{word}",
	"{sub}{num}",
	"{word}{num}",
	"{word}-{sub}-{num}",
	"{sub}-{word}-{num}",
	"{word}{num}-{sub}",
	"{num}-{sub}",
	"{num}.{sub}",
}

// Engine generates subdomain permutations.
type Engine struct {
	words   []string
	verbose bool
}

// New creates a permutation Engine.
func New(extraWords []string, verbose bool) *Engine {
	words := make([]string, 0, len(defaultWords)+len(extraWords))
	words = append(words, defaultWords...)
	for _, w := range extraWords {
		if w != "" {
			words = append(words, w)
		}
	}
	return &Engine{words: dedup(words), verbose: verbose}
}

// Generate produces permutations from discovered subdomains.
// Input: list of subdomains from passive/brute.
// Output: channel of new candidate subdomains.
func (e *Engine) Generate(subdomains []string, domain string) <-chan string {
	out := make(chan string, 10000)

	go func() {
		defer close(out)

		if len(subdomains) == 0 {
			return
		}

		// Extract words from existing subdomains
		extracted := e.extractWords(subdomains, domain)
		allWords := dedup(append(e.words, extracted...))

		seen := make(map[string]struct{})

		for _, sub := range subdomains {
			// Parse the subdomain into components
			subdomain := strings.TrimSuffix(sub, "."+domain)
			if subdomain == domain || subdomain == "" {
				continue
			}

			parts := parseParts(subdomain)
			nums := extractNumbers(subdomain)

			for _, word := range allWords {
				for _, pattern := range patterns {
					candidates := applyPattern(pattern, parts, word, nums, domain)
					for _, c := range candidates {
						if _, ok := seen[c]; ok {
							continue
						}
						seen[c] = struct{}{}
						out <- c
					}
				}
			}

			// Number iteration: dev2 → dev0, dev1, dev3, dev4, dev5
			for _, numCand := range iterateNumbers(subdomain, domain) {
				if _, ok := seen[numCand]; ok {
					continue
				}
				seen[numCand] = struct{}{}
				out <- numCand
			}
		}
	}()

	return out
}

func applyPattern(pattern string, parts []string, word string, nums []string, domain string) []string {
	var results []string

	sub := strings.Join(parts, "-")
	if sub == "" {
		return nil
	}

	// Apply pattern with word
	candidate := pattern
	candidate = strings.ReplaceAll(candidate, "{sub}", sub)
	candidate = strings.ReplaceAll(candidate, "{word}", word)

	// Handle {num} variants
	if strings.Contains(candidate, "{num}") {
		for _, n := range []string{"1", "2", "3", "01", "02"} {
			c := strings.ReplaceAll(candidate, "{num}", n)
			if isValidSubdomain(c) {
				results = append(results, c+"."+domain)
			}
		}
	} else {
		if isValidSubdomain(candidate) {
			results = append(results, candidate+"."+domain)
		}
	}

	return results
}

func parseParts(subdomain string) []string {
	// Split on common separators
	re := regexp.MustCompile(`[-.]`)
	parts := re.Split(subdomain, -1)
	var cleaned []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return cleaned
}

func extractNumbers(s string) []string {
	re := regexp.MustCompile(`\d+`)
	return re.FindAllString(s, -1)
}

// iterateNumbers generates ±5 variants of numbered subdomains.
// e.g., dev2 → dev0, dev1, dev3, dev4, dev5, dev6, dev7
func iterateNumbers(subdomain, domain string) []string {
	var results []string
	re := regexp.MustCompile(`^(.*?)(\d+)(.*)$`)
	m := re.FindStringSubmatch(subdomain)
	if m == nil {
		return nil
	}

	prefix := m[1]
	numStr := m[2]
	suffix := m[3]

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return nil
	}

	for delta := -3; delta <= 5; delta++ {
		n := num + delta
		if n < 0 {
			continue
		}
		candidate := fmt.Sprintf("%s%d%s", prefix, n, suffix)
		if isValidSubdomain(candidate) {
			results = append(results, candidate+"."+domain)
		}
	}

	return results
}

// extractWords extracts meaningful words from subdomains.
func (e *Engine) extractWords(subdomains []string, domain string) []string {
	wordSet := make(map[string]struct{})
	re := regexp.MustCompile(`[^a-z0-9]+`)

	for _, sub := range subdomains {
		sub = strings.TrimSuffix(sub, "."+domain)
		parts := re.Split(sub, -1)
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) >= 2 && len(p) <= 20 && !isNumeric(p) {
				wordSet[p] = struct{}{}
			}
		}
	}

	words := make([]string, 0, len(wordSet))
	for w := range wordSet {
		words = append(words, w)
	}
	return words
}

var subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`)

func isValidSubdomain(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	return subdomainRe.MatchString(s)
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func dedup(words []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(words))
	for _, w := range words {
		if _, ok := seen[w]; !ok {
			seen[w] = struct{}{}
			result = append(result, w)
		}
	}
	return result
}
