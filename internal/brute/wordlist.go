package brute

import (
	"bufio"
	_ "embed"
	"os"
	"strings"
)

//go:embed default_wordlist.txt
var defaultWordlist string

// LoadWordlist streams words from a file (or uses embedded default).
// Returns a channel for memory-efficient loading of huge wordlists.
func LoadWordlist(path string) (<-chan string, error) {
	out := make(chan string, 1000)

	if path == "" {
		// Use embedded default
		go func() {
			defer close(out)
			for _, line := range strings.Split(defaultWordlist, "\n") {
				word := strings.ToLower(strings.TrimSpace(line))
				if word == "" || strings.HasPrefix(word, "#") {
					continue
				}
				out <- word
			}
		}()
		return out, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(out)
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		for scanner.Scan() {
			word := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}
			out <- word
		}
	}()

	return out, nil
}

// WordsToSlice reads all words from channel into a slice.
// Only use for small wordlists.
func WordsToSlice(ch <-chan string) []string {
	var words []string
	for w := range ch {
		words = append(words, w)
	}
	return words
}

// PrioritizeWords reorders words: known-high-value first.
func PrioritizeWords(words []string, extracted []string) []string {
	priority := map[string]int{
		"www": 1, "api": 2, "mail": 3, "remote": 4, "blog": 5,
		"webmail": 6, "server": 7, "ns1": 8, "ns2": 9, "smtp": 10,
		"secure": 11, "vpn": 12, "admin": 13, "portal": 14, "app": 15,
		"dev": 16, "staging": 17, "test": 18, "prod": 19, "beta": 20,
		"cdn": 21, "media": 22, "static": 23, "img": 24, "images": 25,
		"ftp": 26, "ssh": 27, "git": 28, "gitlab": 29, "jenkins": 30,
		"dashboard": 31, "status": 32, "monitor": 33, "auth": 34, "sso": 35,
		"login": 36, "account": 37, "shop": 38, "store": 39, "pay": 40,
		"payment": 41, "checkout": 42, "support": 43, "help": 44, "docs": 45,
		"developer": 46, "internal": 47, "intranet": 48, "confluence": 49, "jira": 50,
		"mobile": 51, "download": 52, "update": 53, "upload": 54, "files": 55,
		"assets": 56, "preview": 57, "demo": 58, "sandbox": 59, "uat": 60,
		"qa": 61, "integration": 62, "api-v1": 63, "api-v2": 64, "graphql": 65,
		"grpc": 66, "ws": 67, "websocket": 68, "socket": 69, "stream": 70,
	}

	// Add extracted words as high-priority
	for i, w := range extracted {
		priority[w] = i + 1
	}

	high := []string{}
	low := []string{}

	for _, w := range words {
		if _, ok := priority[w]; ok {
			high = append(high, w)
		} else {
			low = append(low, w)
		}
	}

	return append(high, low...)
}
