package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ghostsub/internal/config"
	"github.com/ghostsub/internal/runner"
	"github.com/spf13/cobra"
)

const banner = `
 _       __     __           __
| |     / /__  / /___  _____/ /____  _  __
| | /| / / _ \/ / __ \/ ___/ __/ _ \| |/_/
| |/ |/ /  __/ / /_/ / /__/ /_/  __/>  <
|__/|__/\___/_/\____/\___/\__/\___/_/|_|

subdomain enumeration tool
passive | brute | permute
by inSudo X Claude
`

var (
	flagDomain         string
	flagDomainList     string
	flagModes          string
	flagWordlist       string
	flagThreads        int
	flagOutput         string
	flagOutputJSON     string
	flagSilent         bool
	flagVerbose        bool
	flagNoColor        bool
	flagNoWildcard     bool
	flagSources        string
	flagExcludeSources string
	flagResumeFile     string
	flagParallel       int
	flagRecursive      bool
	flagConfigFile     string
	flagTimeout        int
)

var rootCmd = &cobra.Command{
	Use:   "ghostsub",
	Short: "Subdomain enumeration: passive, brute, permute",
	Long:  banner,
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVarP(&flagDomain, "domain", "d", "", "target domain")
	rootCmd.Flags().StringVarP(&flagDomainList, "list", "l", "", "file with list of domains")
	rootCmd.Flags().StringVarP(&flagModes, "mode", "m", "passive", "modes: passive,brute,permute,all (comma-separated)")
	rootCmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "wordlist for brute (uses embedded default if not set)")
	rootCmd.Flags().IntVarP(&flagThreads, "threads", "t", 100, "number of concurrent DNS threads")
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file (txt)")
	rootCmd.Flags().StringVar(&flagOutputJSON, "json", "", "output file (json)")
	rootCmd.Flags().BoolVarP(&flagSilent, "silent", "s", false, "only output subdomains (no status)")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output")
	rootCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	rootCmd.Flags().BoolVar(&flagNoWildcard, "no-wildcard-filter", false, "disable wildcard filtering")
	rootCmd.Flags().StringVar(&flagSources, "sources", "", "passive sources to use (comma-separated)")
	rootCmd.Flags().StringVar(&flagExcludeSources, "exclude-sources", "", "passive sources to exclude (comma-separated)")
	rootCmd.Flags().StringVar(&flagResumeFile, "resume", "", "resume brute-force from checkpoint file")
	rootCmd.Flags().IntVar(&flagParallel, "parallel", 1, "max parallel domain scans (for -l mode)")
	rootCmd.Flags().BoolVar(&flagRecursive, "recursive", false, "recursive brute-force on discovered subdomains")
	rootCmd.Flags().StringVar(&flagConfigFile, "config", "", "config file with API keys (yaml)")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 15, "HTTP timeout in seconds")
}

func run(cmd *cobra.Command, args []string) error {
	if !flagSilent {
		fmt.Print(banner)
	}

	if flagDomain == "" && flagDomainList == "" {
		return fmt.Errorf("specify -d <domain> or -l <domains-file>")
	}

	cfg := config.DefaultConfig()

	// Parse modes
	modes := strings.Split(strings.ToLower(flagModes), ",")
	for _, m := range modes {
		m = strings.TrimSpace(m)
		switch m {
		case "all":
			cfg.Passive = true
			cfg.Brute = true
			cfg.Permute = true
		case "passive":
			cfg.Passive = true
		case "brute":
			cfg.Brute = true
		case "permute":
			cfg.Permute = true
		}
	}

	cfg.Wordlist = flagWordlist
	cfg.Threads = flagThreads
	cfg.OutputFile = flagOutput
	cfg.OutputJSON = flagOutputJSON
	cfg.Silent = flagSilent
	cfg.Verbose = flagVerbose
	cfg.NoColor = flagNoColor
	cfg.NoWildcardFilter = flagNoWildcard
	cfg.ResumeFile = flagResumeFile
	cfg.Parallel = flagParallel
	cfg.Recursive = flagRecursive
	cfg.HTTPTimeout = time.Duration(flagTimeout) * time.Second

	if flagSources != "" {
		for _, s := range strings.Split(flagSources, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.Sources = append(cfg.Sources, s)
			}
		}
	}

	if flagExcludeSources != "" {
		for _, s := range strings.Split(flagExcludeSources, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.ExcludeSources = append(cfg.ExcludeSources, s)
			}
		}
	}

	// Load API keys from config file
	if flagConfigFile != "" {
		keys, err := config.LoadAPIConfig(flagConfigFile)
		if err != nil {
			fmt.Printf("[warn] could not load config: %v\n", err)
		} else {
			cfg.APIKeys = keys
		}
	}

	// Collect domains
	var domains []string
	if flagDomain != "" {
		domains = append(domains, strings.ToLower(strings.TrimSpace(flagDomain)))
	}

	if flagDomainList != "" {
		listed, err := readDomainList(flagDomainList)
		if err != nil {
			return fmt.Errorf("read domain list: %w", err)
		}
		domains = append(domains, listed...)
	}

	if len(domains) == 0 {
		return fmt.Errorf("no domains specified")
	}

	// Remove duplicates
	domains = dedupStrings(domains)

	// Build a cancellable context with SIGINT/SIGTERM support
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !flagSilent {
			fmt.Println("\n[ghostsub] interrupted — saving partial results...")
		}
		cancel()
	}()

	if len(domains) == 1 {
		cfg.Domain = domains[0]
		r, err := runner.New(cfg)
		if err != nil {
			return err
		}
		return r.Run(ctx, domains[0])
	}

	// Multi-domain
	r, err := runner.New(cfg)
	if err != nil {
		return err
	}
	return r.RunMulti(ctx, domains)
}

func readDomainList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
