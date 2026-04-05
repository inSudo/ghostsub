package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all runtime configuration.
type Config struct {
	// Modes
	Passive bool
	Brute   bool
	Permute bool
	Verify  bool

	// Target
	Domain  string
	Domains []string

	// Passive
	Sources        []string
	ExcludeSources []string

	// Brute
	Wordlist    string
	Threads     int
	Recursive   bool
	ResumeFile  string

	// Resolver
	Resolvers     []string
	TrustedDNS    []string
	DNSTimeout    time.Duration
	DNSRetries    int

	// HTTP
	HTTPTimeout time.Duration
	MaxRetries  int

	// Output
	OutputFile     string
	OutputJSON     string
	Silent         bool
	Verbose        bool
	NoColor        bool
	NoWildcardFilter bool

	// Multi-domain parallel
	Parallel int

	// API Keys (optional)
	APIKeys map[string]string
}

// APIConfig is the YAML config file structure.
type APIConfig struct {
	Keys map[string]string `yaml:"keys"`
}

// DefaultConfig returns sane defaults.
func DefaultConfig() *Config {
	return &Config{
		Passive:     true,
		Brute:       false,
		Permute:     false,
		Verify:      true,
		Threads:     100,
		DNSTimeout:  5 * time.Second,
		DNSRetries:  3,
		HTTPTimeout: 15 * time.Second,
		MaxRetries:  3,
		Parallel:    1,
		TrustedDNS: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"9.9.9.9:53",
			"8.8.4.4:53",
		},
		APIKeys: make(map[string]string),
	}
}

// LoadAPIConfig loads optional YAML config with API keys.
func LoadAPIConfig(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg APIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Keys == nil {
		cfg.Keys = make(map[string]string)
	}
	return cfg.Keys, nil
}

// HasKey returns true if an API key exists for the given source.
func (c *Config) HasKey(source string) bool {
	_, ok := c.APIKeys[source]
	return ok
}

// GetKey returns the API key for a source.
func (c *Config) GetKey(source string) string {
	return c.APIKeys[source]
}
