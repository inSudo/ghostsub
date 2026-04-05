package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ghostsub/pkg/httpclient"
)

// ─── HackerTarget ────────────────────────────────────────────────────────────

type HackerTarget struct {
	client *httpclient.Client
}

func NewHackerTarget() *HackerTarget {
	return &HackerTarget{client: httpclient.New(20*time.Second, 3)}
}

func (s *HackerTarget) Name() string   { return "hackertarget" }
func (s *HackerTarget) NeedsKey() bool { return false }
func (s *HackerTarget) RateLimit() int { return 0 }

func (s *HackerTarget) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://api.hackertarget.com/hostsearch/?q=" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}
		for _, line := range strings.Split(string(body), "\n") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 0 {
				continue
			}
			sub := strings.ToLower(strings.TrimSpace(parts[0]))
			if sub == "" || strings.Contains(sub, "API count") {
				continue
			}
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── AlienVault OTX ──────────────────────────────────────────────────────────

type AlienVault struct {
	client *httpclient.Client
}

func NewAlienVault() *AlienVault {
	return &AlienVault{client: httpclient.New(20*time.Second, 3)}
}

func (s *AlienVault) Name() string   { return "alienvault" }
func (s *AlienVault) NeedsKey() bool { return false }
func (s *AlienVault) RateLimit() int { return 0 }

func (s *AlienVault) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)

		page := 1
		for {
			if ctx.Err() != nil {
				return
			}
			u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?limit=500&page=%d", domain, page)
			body, status, err := s.client.Get(ctx, u)
			if err != nil || status != 200 {
				return
			}

			type entry struct {
				Hostname string `json:"hostname"`
			}
			type resp struct {
				PassiveDNS []entry `json:"passive_dns"`
				HasNext    bool    `json:"has_next"`
			}

			var r resp
			if err := json.Unmarshal(body, &r); err != nil {
				return
			}

			for _, e := range r.PassiveDNS {
				sub := strings.ToLower(strings.TrimSpace(e.Hostname))
				if !strings.HasSuffix(sub, "."+domain) && sub != domain {
					continue
				}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}

			if !r.HasNext {
				return
			}
			page++
			time.Sleep(500 * time.Millisecond)
		}
	}()
	return out
}

// ─── URLScan.io ───────────────────────────────────────────────────────────────

type URLScan struct {
	client *httpclient.Client
}

func NewURLScan() *URLScan {
	return &URLScan{client: httpclient.New(20*time.Second, 3)}
}

func (s *URLScan) Name() string   { return "urlscan" }
func (s *URLScan) NeedsKey() bool { return false }
func (s *URLScan) RateLimit() int { return 0 }

func (s *URLScan) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)

		searchAfter := ""
		for {
			if ctx.Err() != nil {
				return
			}
			u := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain%%3A%s&size=100", domain)
			if searchAfter != "" {
				u += "&search_after=" + url.QueryEscape(searchAfter)
			}

			body, status, err := s.client.Get(ctx, u)
			if err != nil || status != 200 {
				return
			}

			type page struct {
				Domain string `json:"domain"`
			}
			type result struct {
				Page page `json:"page"`
			}
			type resp struct {
				Results []result `json:"results"`
				Total   int      `json:"total"`
			}

			var r resp
			if err := json.Unmarshal(body, &r); err != nil {
				return
			}

			for _, res := range r.Results {
				sub := strings.ToLower(strings.TrimSpace(res.Page.Domain))
				if !strings.HasSuffix(sub, "."+domain) && sub != domain {
					continue
				}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}

			if len(r.Results) < 100 {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	return out
}

// ─── Wayback Machine ──────────────────────────────────────────────────────────

type Wayback struct {
	client *httpclient.Client
}

func NewWayback() *Wayback {
	return &Wayback{client: httpclient.New(25*time.Second, 3)}
}

func (s *Wayback) Name() string   { return "wayback" }
func (s *Wayback) NeedsKey() bool { return false }
func (s *Wayback) RateLimit() int { return 0 }

func (s *Wayback) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 200)
	go func() {
		defer close(out)
		u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=10000", domain)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, line := range strings.Split(string(body), "\n") {
			matches := subRe.FindAllString(line, -1)
			for _, m := range matches {
				sub := strings.ToLower(strings.TrimSpace(m))
				if _, ok := seen[sub]; ok {
					continue
				}
				seen[sub] = struct{}{}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// ─── ThreatMiner ─────────────────────────────────────────────────────────────

type ThreatMiner struct {
	client *httpclient.Client
}

func NewThreatMiner() *ThreatMiner {
	return &ThreatMiner{client: httpclient.New(20*time.Second, 3)}
}

func (s *ThreatMiner) Name() string   { return "threatminer" }
func (s *ThreatMiner) NeedsKey() bool { return false }
func (s *ThreatMiner) RateLimit() int { return 0 }

func (s *ThreatMiner) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://api.threatminer.org/v2/domain.php?q=" + domain + "&rt=5"
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		type resp struct {
			Results []string `json:"results"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Results {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── Anubis-DB / jldc.me ─────────────────────────────────────────────────────

type Anubis struct {
	client *httpclient.Client
}

func NewAnubis() *Anubis {
	return &Anubis{client: httpclient.New(20*time.Second, 3)}
}

func (s *Anubis) Name() string   { return "anubis" }
func (s *Anubis) NeedsKey() bool { return false }
func (s *Anubis) RateLimit() int { return 0 }

func (s *Anubis) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://jldc.me/anubis/subdomains/" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		var subs []string
		if err := json.Unmarshal(body, &subs); err != nil {
			return
		}

		for _, sub := range subs {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── CertSpotter ─────────────────────────────────────────────────────────────

type CertSpotter struct {
	client *httpclient.Client
}

func NewCertSpotter() *CertSpotter {
	return &CertSpotter{client: httpclient.New(20*time.Second, 3)}
}

func (s *CertSpotter) Name() string   { return "certspotter" }
func (s *CertSpotter) NeedsKey() bool { return false }
func (s *CertSpotter) RateLimit() int { return 0 }

func (s *CertSpotter) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		type issuance struct {
			DNSNames []string `json:"dns_names"`
		}

		var results []issuance
		if err := json.Unmarshal(body, &results); err != nil {
			return
		}

		seen := make(map[string]struct{})
		for _, r := range results {
			for _, name := range r.DNSNames {
				sub := strings.ToLower(strings.TrimSpace(name))
				sub = strings.TrimPrefix(sub, "*.")
				if !strings.HasSuffix(sub, "."+domain) && sub != domain {
					continue
				}
				if _, ok := seen[sub]; ok {
					continue
				}
				seen[sub] = struct{}{}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// ─── RapidDNS ────────────────────────────────────────────────────────────────

type RapidDNS struct {
	client *httpclient.Client
}

func NewRapidDNS() *RapidDNS {
	return &RapidDNS{client: httpclient.New(20*time.Second, 3)}
}

func (s *RapidDNS) Name() string   { return "rapiddns" }
func (s *RapidDNS) NeedsKey() bool { return false }
func (s *RapidDNS) RateLimit() int { return 0 }

func (s *RapidDNS) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── SubdomainCenter ─────────────────────────────────────────────────────────

type SubdomainCenter struct {
	client *httpclient.Client
}

func NewSubdomainCenter() *SubdomainCenter {
	return &SubdomainCenter{client: httpclient.New(20*time.Second, 3)}
}

func (s *SubdomainCenter) Name() string   { return "subdomaincenter" }
func (s *SubdomainCenter) NeedsKey() bool { return false }
func (s *SubdomainCenter) RateLimit() int { return 0 }

func (s *SubdomainCenter) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://api.subdomain.center/?domain=" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		var subs []string
		if err := json.Unmarshal(body, &subs); err != nil {
			return
		}

		for _, sub := range subs {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── BufferOver ──────────────────────────────────────────────────────────────

type BufferOver struct {
	client *httpclient.Client
}

func NewBufferOver() *BufferOver {
	return &BufferOver{client: httpclient.New(20*time.Second, 3)}
}

func (s *BufferOver) Name() string   { return "bufferover" }
func (s *BufferOver) NeedsKey() bool { return false }
func (s *BufferOver) RateLimit() int { return 0 }

func (s *BufferOver) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://dns.bufferover.run/dns?q=." + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		type resp struct {
			RDNS []string `json:"RDNS"`
			FDNS []string `json:"FDNS_A"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		all := append(r.RDNS, r.FDNS...)
		seen := make(map[string]struct{})
		for _, entry := range all {
			// Format: "1.2.3.4,sub.domain.com"
			parts := strings.SplitN(entry, ",", 2)
			if len(parts) != 2 {
				continue
			}
			sub := strings.ToLower(strings.TrimSpace(parts[1]))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── LeakIX ──────────────────────────────────────────────────────────────────

type LeakIX struct {
	client *httpclient.Client
}

func NewLeakIX() *LeakIX {
	return &LeakIX{client: httpclient.New(20*time.Second, 3)}
}

func (s *LeakIX) Name() string   { return "leakix" }
func (s *LeakIX) NeedsKey() bool { return false }
func (s *LeakIX) RateLimit() int { return 0 }

func (s *LeakIX) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://leakix.net/api/subdomains/" + domain
		headers := map[string]string{"Accept": "application/json"}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type entry struct {
			Subdomain string `json:"subdomain"`
		}
		var entries []entry
		if err := json.Unmarshal(body, &entries); err != nil {
			return
		}

		for _, e := range entries {
			sub := strings.ToLower(strings.TrimSpace(e.Subdomain))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── CommonCrawl ─────────────────────────────────────────────────────────────

type CommonCrawl struct {
	client *httpclient.Client
}

func NewCommonCrawl() *CommonCrawl {
	return &CommonCrawl{client: httpclient.New(30*time.Second, 3)}
}

func (s *CommonCrawl) Name() string   { return "commoncrawl" }
func (s *CommonCrawl) NeedsKey() bool { return false }
func (s *CommonCrawl) RateLimit() int { return 0 }

func (s *CommonCrawl) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 200)
	go func() {
		defer close(out)

		// Get latest index
		idxBody, status, err := s.client.Get(ctx, "https://index.commoncrawl.org/collinfo.json")
		if err != nil || status != 200 {
			return
		}

		type collInfo struct {
			ID string `json:"id"`
		}
		var colls []collInfo
		if err := json.Unmarshal(idxBody, &colls); err != nil || len(colls) == 0 {
			return
		}

		// Use latest index
		latestID := colls[0].ID
		u := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=*.%s&output=text&fl=url&limit=5000", latestID, domain)

		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, line := range strings.Split(string(body), "\n") {
			for _, m := range subRe.FindAllString(line, -1) {
				sub := strings.ToLower(strings.TrimSpace(m))
				if _, ok := seen[sub]; ok {
					continue
				}
				seen[sub] = struct{}{}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// ─── DNSRepo ──────────────────────────────────────────────────────────────────

type DNSRepo struct {
	client *httpclient.Client
}

func NewDNSRepo() *DNSRepo {
	return &DNSRepo{client: httpclient.New(20*time.Second, 3)}
}

func (s *DNSRepo) Name() string   { return "dnsrepo" }
func (s *DNSRepo) NeedsKey() bool { return false }
func (s *DNSRepo) RateLimit() int { return 0 }

func (s *DNSRepo) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://dnsrepo.noc.org/?search=" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── SiteDossier ─────────────────────────────────────────────────────────────

type SiteDossier struct {
	client *httpclient.Client
}

func NewSiteDossier() *SiteDossier {
	return &SiteDossier{client: httpclient.New(20*time.Second, 3)}
}

func (s *SiteDossier) Name() string   { return "sitedossier" }
func (s *SiteDossier) NeedsKey() bool { return false }
func (s *SiteDossier) RateLimit() int { return 0 }

func (s *SiteDossier) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "http://www.sitedossier.com/site/" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})
		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── VirusTotal (optional key) ────────────────────────────────────────────────

type VirusTotal struct {
	client *httpclient.Client
	apiKey string
}

func NewVirusTotal(apiKey string) *VirusTotal {
	return &VirusTotal{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *VirusTotal) Name() string   { return "virustotal" }
func (s *VirusTotal) NeedsKey() bool { return true }
func (s *VirusTotal) RateLimit() int { return 4 }

func (s *VirusTotal) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		cursor := ""
		for {
			if ctx.Err() != nil {
				return
			}
			u := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
			if cursor != "" {
				u += "&cursor=" + cursor
			}

			headers := map[string]string{"x-apikey": s.apiKey}
			body, status, err := s.client.GetWithHeaders(ctx, u, headers)
			if err != nil || status != 200 {
				return
			}

			type vtEntry struct {
				ID string `json:"id"`
			}
			type vtResp struct {
				Data []vtEntry `json:"data"`
				Meta struct {
					Cursor string `json:"cursor"`
				} `json:"meta"`
			}

			var r vtResp
			if err := json.Unmarshal(body, &r); err != nil {
				return
			}

			for _, e := range r.Data {
				sub := strings.ToLower(strings.TrimSpace(e.ID))
				if !strings.HasSuffix(sub, "."+domain) && sub != domain {
					continue
				}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}

			if r.Meta.Cursor == "" {
				return
			}
			cursor = r.Meta.Cursor
			time.Sleep(250 * time.Millisecond)
		}
	}()
	return out
}

// ─── SecurityTrails (optional key) ────────────────────────────────────────────

type SecurityTrails struct {
	client *httpclient.Client
	apiKey string
}

func NewSecurityTrails(apiKey string) *SecurityTrails {
	return &SecurityTrails{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *SecurityTrails) Name() string   { return "securitytrails" }
func (s *SecurityTrails) NeedsKey() bool { return true }
func (s *SecurityTrails) RateLimit() int { return 0 }

func (s *SecurityTrails) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true", domain)
		headers := map[string]string{"APIKEY": s.apiKey, "Accept": "application/json"}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type resp struct {
			Subdomains []string `json:"subdomains"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Subdomains {
			full := strings.ToLower(strings.TrimSpace(sub)) + "." + domain
			select {
			case out <- full:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── DNSDumpster (requires CSRF) ─────────────────────────────────────────────

type DNSDumpster struct {
	client *httpclient.Client
}

func NewDNSDumpster() *DNSDumpster {
	return &DNSDumpster{client: httpclient.New(30*time.Second, 3)}
}

func (s *DNSDumpster) Name() string   { return "dnsdumpster" }
func (s *DNSDumpster) NeedsKey() bool { return false }
func (s *DNSDumpster) RateLimit() int { return 0 }

func (s *DNSDumpster) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)

		// Step 1: Get CSRF token from homepage
		homeBody, status, err := s.client.Get(ctx, "https://dnsdumpster.com/")
		if err != nil || status != 200 {
			return
		}

		csrfToken := extractCSRFToken(string(homeBody))
		if csrfToken == "" {
			return
		}

		// Step 2: POST with CSRF token
		formData := map[string]string{
			"csrfmiddlewaretoken": csrfToken,
			"targetip":            domain,
			"user":                "free",
		}
		headers := map[string]string{
			"Referer":      "https://dnsdumpster.com/",
			"Cookie":       "csrftoken=" + csrfToken,
			"Content-Type": "application/x-www-form-urlencoded",
		}

		body, status, err := s.client.PostForm(ctx, "https://dnsdumpster.com/", formData, headers)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func extractCSRFToken(body string) string {
	re := regexp.MustCompile(`name=['"]csrfmiddlewaretoken['"] value=['"]([^'"]+)['"]`)
	m := re.FindStringSubmatch(body)
	if len(m) > 1 {
		return m[1]
	}
	// Also try meta tag
	re2 := regexp.MustCompile(`<meta name=['"]csrf-token['"] content=['"]([^'"]+)['"]`)
	m2 := re2.FindStringSubmatch(body)
	if len(m2) > 1 {
		return m2[1]
	}
	return ""
}

// ─── Riddler.io ──────────────────────────────────────────────────────────────

type Riddler struct {
	client *httpclient.Client
}

func NewRiddler() *Riddler {
	return &Riddler{client: httpclient.New(20*time.Second, 3)}
}

func (s *Riddler) Name() string   { return "riddler" }
func (s *Riddler) NeedsKey() bool { return false }
func (s *Riddler) RateLimit() int { return 0 }

func (s *Riddler) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://riddler.io/search/exportcsv?q=pssl:" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, line := range strings.Split(string(body), "\n") {
			for _, m := range subRe.FindAllString(line, -1) {
				sub := strings.ToLower(strings.TrimSpace(m))
				if _, ok := seen[sub]; ok {
					continue
				}
				seen[sub] = struct{}{}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// ─── FullHunt (optional key) ──────────────────────────────────────────────────

type FullHunt struct {
	client *httpclient.Client
	apiKey string
}

func NewFullHunt(apiKey string) *FullHunt {
	return &FullHunt{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *FullHunt) Name() string   { return "fullhunt" }
func (s *FullHunt) NeedsKey() bool { return true }
func (s *FullHunt) RateLimit() int { return 0 }

func (s *FullHunt) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := "https://fullhunt.io/api/v1/domain/" + domain + "/subdomains"
		headers := map[string]string{"X-API-KEY": s.apiKey}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type resp struct {
			Hosts []string `json:"hosts"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Hosts {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── Bevigil (optional key) ───────────────────────────────────────────────────

type Bevigil struct {
	client *httpclient.Client
	apiKey string
}

func NewBevigil(apiKey string) *Bevigil {
	return &Bevigil{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *Bevigil) Name() string   { return "bevigil" }
func (s *Bevigil) NeedsKey() bool { return true }
func (s *Bevigil) RateLimit() int { return 0 }

func (s *Bevigil) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain)
		headers := map[string]string{"X-Access-Token": s.apiKey}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type resp struct {
			Subdomains []string `json:"subdomains"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Subdomains {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── Netlas (optional key) ────────────────────────────────────────────────────

type Netlas struct {
	client *httpclient.Client
	apiKey string
}

func NewNetlas(apiKey string) *Netlas {
	return &Netlas{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *Netlas) Name() string   { return "netlas" }
func (s *Netlas) NeedsKey() bool { return true }
func (s *Netlas) RateLimit() int { return 0 }

func (s *Netlas) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := fmt.Sprintf("https://app.netlas.io/api/domains/?q=domain:*.%s&source_type=include&start=0&fields=domain", domain)
		headers := map[string]string{"X-API-Key": s.apiKey}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type item struct {
			Data struct {
				Domain string `json:"domain"`
			} `json:"data"`
		}
		type resp struct {
			Items []item `json:"items"`
		}
		var r resp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, e := range r.Items {
			sub := strings.ToLower(strings.TrimSpace(e.Data.Domain))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── GitHub Search (scrape, no key needed but rate limited) ──────────────────

type GitHub struct {
	client *httpclient.Client
	token  string
}

func NewGitHub(token string) *GitHub {
	return &GitHub{client: httpclient.New(20*time.Second, 3), token: token}
}

func (s *GitHub) Name() string   { return "github" }
func (s *GitHub) NeedsKey() bool { return false }
func (s *GitHub) RateLimit() int { return 0 }

func (s *GitHub) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)

		headers := map[string]string{}
		if s.token != "" {
			headers["Authorization"] = "token " + s.token
		}

		// Search code for domain references
		queries := []string{
			fmt.Sprintf("https://api.github.com/search/code?q=%22.%s%22&per_page=100", domain),
			fmt.Sprintf("https://api.github.com/search/commits?q=%22.%s%22&per_page=100", domain),
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, q := range queries {
			if ctx.Err() != nil {
				return
			}
			body, status, err := s.client.GetWithHeaders(ctx, q, headers)
			if err != nil || (status != 200 && status != 422) {
				time.Sleep(2 * time.Second)
				continue
			}

			for _, m := range subRe.FindAllString(string(body), -1) {
				sub := strings.ToLower(strings.TrimSpace(m))
				if _, ok := seen[sub]; ok {
					continue
				}
				seen[sub] = struct{}{}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}
			time.Sleep(3 * time.Second) // GitHub rate limit
		}
	}()
	return out
}

// ─── Shodan (optional key) ────────────────────────────────────────────────────

type Shodan struct {
	client *httpclient.Client
	apiKey string
}

func NewShodan(apiKey string) *Shodan {
	return &Shodan{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *Shodan) Name() string   { return "shodan" }
func (s *Shodan) NeedsKey() bool { return true }
func (s *Shodan) RateLimit() int { return 0 }

func (s *Shodan) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, s.apiKey)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		type shodanResp struct {
			Subdomains []string `json:"subdomains"`
		}
		var r shodanResp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Subdomains {
			full := strings.ToLower(strings.TrimSpace(sub)) + "." + domain
			select {
			case out <- full:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── BinaryEdge (optional key) ────────────────────────────────────────────────

type BinaryEdge struct {
	client *httpclient.Client
	apiKey string
}

func NewBinaryEdge(apiKey string) *BinaryEdge {
	return &BinaryEdge{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *BinaryEdge) Name() string   { return "binaryedge" }
func (s *BinaryEdge) NeedsKey() bool { return true }
func (s *BinaryEdge) RateLimit() int { return 0 }

func (s *BinaryEdge) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		page := 1
		for {
			if ctx.Err() != nil {
				return
			}
			u := fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d", domain, page)
			headers := map[string]string{"X-Key": s.apiKey}
			body, status, err := s.client.GetWithHeaders(ctx, u, headers)
			if err != nil || status != 200 {
				return
			}

			type beResp struct {
				Events   []string `json:"events"`
				PageSize int      `json:"pagesize"`
				Total    int      `json:"total"`
			}
			var r beResp
			if err := json.Unmarshal(body, &r); err != nil {
				return
			}

			for _, sub := range r.Events {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if !strings.HasSuffix(sub, "."+domain) && sub != domain {
					continue
				}
				select {
				case out <- sub:
				case <-ctx.Done():
					return
				}
			}

			if len(r.Events) < r.PageSize || r.PageSize == 0 {
				return
			}
			page++
			time.Sleep(200 * time.Millisecond)
		}
	}()
	return out
}

// ─── PassiveTotal / RiskIQ (optional key) ────────────────────────────────────

type PassiveTotal struct {
	client   *httpclient.Client
	username string
	apiKey   string
}

func NewPassiveTotal(username, apiKey string) *PassiveTotal {
	return &PassiveTotal{client: httpclient.New(20*time.Second, 3), username: username, apiKey: apiKey}
}

func (s *PassiveTotal) Name() string   { return "passivetotal" }
func (s *PassiveTotal) NeedsKey() bool { return true }
func (s *PassiveTotal) RateLimit() int { return 0 }

func (s *PassiveTotal) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" || s.username == "" {
			return
		}

		u := "https://api.passivetotal.org/v2/enrichment/subdomains?query=" + domain

		// Basic auth
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		req.SetBasicAuth(s.username, s.apiKey)
		req.Header.Set("Accept", "application/json")

		httpClient := &http.Client{Timeout: 20 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		type ptResp struct {
			Subdomains []string `json:"subdomains"`
		}
		var r ptResp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Subdomains {
			full := strings.ToLower(strings.TrimSpace(sub)) + "." + domain
			select {
			case out <- full:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── Chaos (ProjectDiscovery) ────────────────────────────────────────────────

type Chaos struct {
	client *httpclient.Client
	apiKey string
}

func NewChaos(apiKey string) *Chaos {
	return &Chaos{client: httpclient.New(20*time.Second, 3), apiKey: apiKey}
}

func (s *Chaos) Name() string   { return "chaos" }
func (s *Chaos) NeedsKey() bool { return true }
func (s *Chaos) RateLimit() int { return 0 }

func (s *Chaos) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 200)
	go func() {
		defer close(out)
		if s.apiKey == "" {
			return
		}

		u := "https://dns.projectdiscovery.io/dns/" + domain + "/subdomains"
		headers := map[string]string{"Authorization": s.apiKey}
		body, status, err := s.client.GetWithHeaders(ctx, u, headers)
		if err != nil || status != 200 {
			return
		}

		type chaosResp struct {
			Subdomains []string `json:"subdomains"`
			Domain     string   `json:"domain"`
		}
		var r chaosResp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		for _, sub := range r.Subdomains {
			full := strings.ToLower(strings.TrimSpace(sub)) + "." + domain
			select {
			case out <- full:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── FOFA (optional key) ──────────────────────────────────────────────────────

type FOFA struct {
	client *httpclient.Client
	email  string
	apiKey string
}

func NewFOFA(email, apiKey string) *FOFA {
	return &FOFA{client: httpclient.New(20*time.Second, 3), email: email, apiKey: apiKey}
}

func (s *FOFA) Name() string   { return "fofa" }
func (s *FOFA) NeedsKey() bool { return true }
func (s *FOFA) RateLimit() int { return 0 }

func (s *FOFA) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		if s.apiKey == "" || s.email == "" {
			return
		}

		// FOFA query: domain="example.com"
		query := fmt.Sprintf(`domain="%s"`, domain)
		encoded := url.QueryEscape(query)
		u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=host&page=1&size=100",
			s.email, s.apiKey, encoded)

		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		type fofaResp struct {
			Results [][]string `json:"results"`
			Error   bool       `json:"error"`
		}
		var r fofaResp
		if err := json.Unmarshal(body, &r); err != nil {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, row := range r.Results {
			for _, val := range row {
				for _, m := range subRe.FindAllString(val, -1) {
					sub := strings.ToLower(strings.TrimSpace(m))
					if _, ok := seen[sub]; ok {
						continue
					}
					seen[sub] = struct{}{}
					select {
					case out <- sub:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// ─── Digitorus / ViewDNS ──────────────────────────────────────────────────────

type ViewDNS struct {
	client *httpclient.Client
}

func NewViewDNS() *ViewDNS {
	return &ViewDNS{client: httpclient.New(20*time.Second, 3)}
}

func (s *ViewDNS) Name() string   { return "viewdns" }
func (s *ViewDNS) NeedsKey() bool { return false }
func (s *ViewDNS) RateLimit() int { return 0 }

func (s *ViewDNS) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := fmt.Sprintf("https://viewdns.info/reverseip/?host=%s&apiresponseformat=json", domain)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})
		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── Webarchive (alternative endpoint) ────────────────────────────────────────

type Webarchive struct {
	client *httpclient.Client
}

func NewWebarchive() *Webarchive {
	return &Webarchive{client: httpclient.New(25*time.Second, 3)}
}

func (s *Webarchive) Name() string   { return "webarchive" }
func (s *Webarchive) NeedsKey() bool { return false }
func (s *Webarchive) RateLimit() int { return 0 }

func (s *Webarchive) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=5000&fastLatest=true", domain)
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		subRe := regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
		seen := make(map[string]struct{})

		for _, m := range subRe.FindAllString(string(body), -1) {
			sub := strings.ToLower(strings.TrimSpace(m))
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ─── SonarSearch (FDNS dataset) ───────────────────────────────────────────────

type SonarSearch struct {
	client *httpclient.Client
}

func NewSonarSearch() *SonarSearch {
	return &SonarSearch{client: httpclient.New(20*time.Second, 3)}
}

func (s *SonarSearch) Name() string   { return "sonarsearch" }
func (s *SonarSearch) NeedsKey() bool { return false }
func (s *SonarSearch) RateLimit() int { return 0 }

func (s *SonarSearch) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		u := "https://sonar.omnisint.io/subdomains/" + domain
		body, status, err := s.client.Get(ctx, u)
		if err != nil || status != 200 {
			return
		}

		var subs []string
		if err := json.Unmarshal(body, &subs); err != nil {
			return
		}

		for _, sub := range subs {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			select {
			case out <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}


