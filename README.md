<div align="center">

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗██╗   ██╗██████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║   ██║██╔══██╗
 ██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗██║   ██║██████╔╝
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║██║   ██║██╔══██╗
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║╚██████╔╝██████╔╝
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝
```

**Passive · Brute · Permute**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-inSudo-red?style=flat-square&logo=github)](https://github.com/inSudo)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Termux-lightgrey?style=flat-square)]()

> *A subdomain enumeration engine built for hunters who don't stop at the surface.*

</div>

---

## What is GhostSub?

GhostSub is a fast, modular subdomain enumeration tool written in Go. It combines **passive OSINT collection** from 25+ sources, **intelligent DNS brute-force** with adaptive throttling, and a **smart permutation engine** that learns target naming patterns — all running concurrently in a clean pipeline.

Built from scratch for bug bounty hunters who scan dozens of targets a day and need something that actually works under real conditions: slow networks, rate-limited APIs, wildcard DNS, ISP hijacking, and everything in between.

---

## Feature Overview

### Passive Enumeration — 25+ Sources

Concurrent fanout to all sources simultaneously. Per-source 30-second timeout — if one source is lagging, the rest keep running.

| Free (No Key) | Optional API Key |
|---|---|
| crt.sh | VirusTotal |
| HackerTarget | SecurityTrails |
| AlienVault OTX | Shodan |
| URLScan.io | BinaryEdge |
| Wayback Machine CDX | FullHunt |
| ThreatMiner | Bevigil |
| Anubis-DB | Netlas |
| CertSpotter | Chaos (ProjectDiscovery) |
| RapidDNS | FOFA |
| SubdomainCenter | PassiveTotal / RiskIQ |
| BufferOver | GitHub (token) |
| LeakIX | |
| CommonCrawl | |
| DNSRepo | |
| SiteDossier | |
| DNSDumpster | |
| Riddler.io | |
| ViewDNS | |
| Sonar / FDNS | |

### Brute Force Engine

- **Streaming wordlist** — works on wordlists of any size without loading into memory
- **Embedded default wordlist** — 500+ curated words, works out of the box
- **Adaptive thread throttling** — auto-reduces concurrency when network error rate spikes
- **Checkpoint & resume** — interrupted scan? pick up exactly where you left off
- **Recursive mode** — brute-force sub-levels of discovered subdomains

### Smart Permutation Engine

- **Pattern extraction** — analyzes discovered subdomains to detect naming conventions (`dev-api`, `staging-v2`) and generates targeted permutations
- **Number iteration** — finds `api2`? auto-generates `api0`, `api1`, `api3`...`api7`
- **13 pattern templates** with prefix/suffix/separator variations
- **Word enrichment** — extracts meaningful words from existing results and feeds them back into the permutation pool

### DNS Engine

- **50+ public resolvers** with round-robin rotation and per-resolver health tracking
- **Automatic blacklisting** — resolvers that fail 5+ times are temporarily pulled
- **UDP → TCP fallback** on truncated responses
- **ISP NXDOMAIN hijack detection** — detects when your ISP redirects NXDOMAIN
- **Multi-level wildcard detection** — probes with random strings, handles anycast edge cases
- **Double-verification** with trusted resolvers (Google, Cloudflare, Quad9)

### Resilient HTTP Layer

- Exponential backoff with jitter on retries
- Respects `Retry-After` headers on 429 responses
- User-agent rotation across 8 realistic browser UAs
- 10MB response body cap

---

## Install

```bash
git clone https://github.com/inSudo/ghostsub
cd ghostsub
go mod tidy
go build -o ghostsub ./cmd/ghostsub
```

**Requirements:** Go 1.21+

---

## Usage

### Basic

```bash
# Passive enumeration (default)
./ghostsub -d example.com

# All modes: passive + brute + permute
./ghostsub -d example.com -m all

# Passive + brute only
./ghostsub -d example.com -m passive,brute

# Brute with custom wordlist
./ghostsub -d example.com -m brute -w /path/to/wordlist.txt
```

### Output

```bash
# Save to txt
./ghostsub -d example.com -o results.txt

# Save to JSON
./ghostsub -d example.com --json results.json

# Both formats
./ghostsub -d example.com -o results.txt --json results.json

# Silent — only subdomains, pipe-friendly
./ghostsub -d example.com -s
```

### Multi-Target

```bash
# Scan from file
./ghostsub -l domains.txt -m passive

# Parallel scanning (3 domains simultaneously)
./ghostsub -l domains.txt -m passive --parallel 3
```

### Source Control

```bash
# Use specific sources only
./ghostsub -d example.com --sources crtsh,alienvault,urlscan,certspotter

# Exclude noisy sources
./ghostsub -d example.com --exclude-sources hackertarget,riddler

# Verbose — source timing + per-source counts
./ghostsub -d example.com -v
```

### Brute Options

```bash
# More threads
./ghostsub -d example.com -m brute -t 200

# Resume interrupted scan
./ghostsub -d example.com -m brute --resume checkpoint.json

# Recursive brute (sub-levels)
./ghostsub -d example.com -m brute --recursive
```

### Pipeline Integration

```bash
# Pipe to httpx
./ghostsub -d example.com -s | httpx -silent -status-code -title

# Pipe to nuclei
./ghostsub -d example.com -s | nuclei -t technologies/

# Full recon one-liner
./ghostsub -d target.com -m all -t 150 -s -o subs.txt && \
  httpx -l subs.txt -silent -o live.txt && \
  nuclei -l live.txt -t exposures/
```

---

## API Keys (Optional)

Create `~/.config/ghostsub/config.yaml`:

```yaml
keys:
  virustotal: YOUR_VT_KEY
  securitytrails: YOUR_ST_KEY
  shodan: YOUR_SHODAN_KEY
  fullhunt: YOUR_FH_KEY
  bevigil: YOUR_BEVIGIL_KEY
  netlas: YOUR_NETLAS_KEY
  binaryedge: YOUR_BE_KEY
  chaos: YOUR_CHAOS_KEY
  github: YOUR_GITHUB_TOKEN
  fofa_email: you@example.com
  fofa: YOUR_FOFA_KEY
  passivetotal_user: you@example.com
  passivetotal: YOUR_PT_KEY
```

```bash
./ghostsub -d example.com --config ~/.config/ghostsub/config.yaml -m all
```

---

## Architecture

```
ghostsub/
├── cmd/ghostsub/          # CLI entry point (Cobra)
├── internal/
│   ├── runner/            # Pipeline orchestrator
│   ├── passive/
│   │   ├── source.go      # Source interface
│   │   ├── manager.go     # Concurrent fanout to all sources
│   │   └── sources/       # 25+ individual source implementations
│   ├── brute/
│   │   ├── bruteforcer.go # Concurrent DNS brute with adaptive throttle
│   │   └── wordlist.go    # Streaming wordlist loader + priority ordering
│   ├── permute/
│   │   └── engine.go      # Pattern extraction + permutation DSL
│   ├── resolver/
│   │   ├── pool.go        # 50+ resolver pool with health tracking
│   │   ├── resolver.go    # miekg/dns client, TCP fallback, NXDOMAIN hijack
│   │   └── wildcard.go    # Multi-level wildcard detection + filtering
│   ├── output/
│   │   └── writer.go      # Concurrent-safe multi-format output
│   └── config/
│       └── config.go      # Config struct + YAML API key loader
└── pkg/
    └── httpclient/        # Resilient HTTP client (retry/backoff/UA rotation)
```

### Pipeline Flow

```
Target Domain
     │
     ├─► [Wildcard Detection] — random probes → build wildcard IP filter set
     │
     ├─► [Passive Manager] — concurrent fanout (up to 15 sources at once)
     │        ├─ crtsh, alienvault, urlscan, wayback ... 20+ more
     │        └─ per-source 30s timeout, degraded sources skipped silently
     │
     ├─► [Brute Force] — streaming wordlist, 100+ goroutines
     │        ├─ adaptive throttle (auto-reduces threads on high error rate)
     │        ├─ wildcard filter on every hit
     │        └─ checkpoint/resume support
     │
     │   [Dedup + Stream to Output]
     │
     └─► [Permutation Engine] — runs after passive+brute
              ├─ extract naming patterns from discovered subs
              ├─ generate permutations (13 templates)
              ├─ number iteration (dev2 → dev0..dev7)
              └─ resolve each permutation concurrently → wildcard filter
                              │
                              ▼
                       [Final Output]
                  txt · json · stdout
```

---

## Edge Cases Handled

| Scenario | Solution |
|---|---|
| Wildcard DNS (`*.example.com`) | Multi-probe detection + IP frequency analysis + double-verify with trusted resolvers |
| Anycast wildcard | Cross-resolver IP variance detection |
| ISP NXDOMAIN hijacking | Pre-scan random probe to identify hijack IPs |
| Source timeout / server down | Per-source 30s hard timeout, rest continue |
| HTTP 429 Too Many Requests | `Retry-After` header + exponential backoff + jitter |
| Network degradation | Adaptive thread reduction when DNS error rate > 30% |
| Interrupted brute-force | Full checkpoint/resume support |
| Huge wordlists (10M+ lines) | Streaming — zero memory loading |
| Ctrl+C mid-scan | Graceful shutdown, results flushed |
| DNS resolver overload | Per-resolver health tracking, auto-blacklist + rotate |
| UDP truncation | Auto-retry over TCP |
| Malformed JSON from source | Safe unmarshal, source skipped silently |
| Multi-target source rate limits | Global counter tracking across domain scans |

---

## Flags Reference

```
INPUT:
  -d, --domain string          Target domain
  -l, --list string            File containing list of domains

MODE:
  -m, --mode string            Modes: passive,brute,permute,all (default "passive")

BRUTE:
  -w, --wordlist string        Wordlist path (uses embedded default if not set)
  -t, --threads int            Concurrent DNS threads (default 100)
      --recursive              Recursive brute-force on discovered subdomains
      --resume string          Resume brute-force from checkpoint file

OUTPUT:
  -o, --output string          Output file (txt)
      --json string            Output file (json)
  -s, --silent                 Only output subdomains (pipe-friendly)
  -v, --verbose                Verbose — source timings, per-source counts
      --no-color               Disable colored output

SOURCE:
      --sources string         Passive sources to use (comma-separated)
      --exclude-sources string Passive sources to exclude (comma-separated)

CONFIG:
      --config string          YAML config file with API keys
      --timeout int            HTTP timeout in seconds (default 15)

ADVANCED:
      --parallel int           Max parallel domain scans for -l mode (default 1)
      --no-wildcard-filter     Disable wildcard filtering (debug)
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/miekg/dns` | Raw DNS client (UDP/TCP, full protocol control) |
| `github.com/spf13/cobra` | CLI framework |
| `gopkg.in/yaml.v3` | API key config parsing |

Zero bloat. Everything else is standard library.

---

## Author

Built by **[inSudo](https://github.com/inSudo)** — security researcher & bug bounty hunter.
and claude AI
---

## Disclaimer

GhostSub is intended for authorized security assessments and bug bounty programs only. Always ensure you have explicit permission to enumerate subdomains of your target. The author is not responsible for any misuse.

---

<div align="center">

**[github.com/inSudo/ghostsub](https://github.com/inSudo/ghostsub)**

*Hunt smart. Hunt deep.*

</div>
