package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// JSONRecord represents one output record in JSON mode.
type JSONRecord struct {
	Subdomain string   `json:"subdomain"`
	Source    string   `json:"source,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Timestamp string   `json:"timestamp"`
}

// Writer handles multi-format concurrent-safe output.
type Writer struct {
	silent     bool
	noColor    bool
	txtFile    *os.File
	jsonFile    *os.File
	txtWriter   *bufio.Writer
	jsonWriter  *bufio.Writer
	seen        map[string]struct{}
	mu          sync.Mutex
	count       int
}

// New creates a Writer.
func New(silent, noColor bool, txtPath, jsonPath string) (*Writer, error) {
	w := &Writer{
		silent:  silent,
		noColor: noColor,
		seen:    make(map[string]struct{}),
	}

	if txtPath != "" {
		f, err := os.Create(txtPath)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w.txtFile = f
		w.txtWriter = bufio.NewWriter(f)
	}

	if jsonPath != "" {
		f, err := os.Create(jsonPath)
		if err != nil {
			return nil, fmt.Errorf("create json output: %w", err)
		}
		w.jsonFile = f
		w.jsonWriter = bufio.NewWriter(f)
		// Start JSON array
		fmt.Fprintln(w.jsonWriter, "[")
	}

	return w, nil
}

// Write outputs a subdomain (dedup enforced here too as safety net).
func (w *Writer) Write(subdomain, source string, ips []string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	sub := strings.ToLower(strings.TrimSpace(subdomain))
	if sub == "" {
		return false
	}

	if _, ok := w.seen[sub]; ok {
		return false
	}
	w.seen[sub] = struct{}{}
	w.count++

	// stdout
	if !w.silent {
		if !w.noColor {
			fmt.Printf("\033[32m%s\033[0m\n", sub)
		} else {
			fmt.Println(sub)
		}
	}

	// txt file
	if w.txtWriter != nil {
		fmt.Fprintln(w.txtWriter, sub)
	}

	// json file
	if w.jsonWriter != nil {
		record := JSONRecord{
			Subdomain: sub,
			Source:    source,
			IPs:       ips,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		data, _ := json.Marshal(record)

		if w.count > 1 {
			fmt.Fprintf(w.jsonWriter, ",\n")
		}
		fmt.Fprintf(w.jsonWriter, "  %s", data)
	}

	return true
}

// Count returns number of unique subdomains written.
func (w *Writer) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Seen returns whether a subdomain was already written.
func (w *Writer) Seen(sub string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.seen[strings.ToLower(strings.TrimSpace(sub))]
	return ok
}

// Close flushes and closes all output files.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.txtWriter != nil {
		if err := w.txtWriter.Flush(); err != nil {
			return err
		}
		w.txtFile.Close()
	}

	if w.jsonWriter != nil {
		fmt.Fprintln(w.jsonWriter, "\n]")
		if err := w.jsonWriter.Flush(); err != nil {
			return err
		}
		w.jsonFile.Close()
	}

	return nil
}
