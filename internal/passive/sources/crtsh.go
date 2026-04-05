package sources

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ghostsub/pkg/httpclient"
)

type CrtSh struct {
	client *httpclient.Client
}

func NewCrtSh() *CrtSh {
	// crt.sh can be very slow — use longer timeout and more retries
	return &CrtSh{client: httpclient.New(30*time.Second, 5)}
}

func (s *CrtSh) Name() string      { return "crtsh" }
func (s *CrtSh) NeedsKey() bool    { return false }
func (s *CrtSh) RateLimit() int    { return 0 }

func (s *CrtSh) Query(ctx context.Context, domain string) <-chan string {
	out := make(chan string, 200)

	go func() {
		defer close(out)

		url := "https://crt.sh/?q=%25." + domain + "&output=json"
		body, status, err := s.client.Get(ctx, url)
		if err != nil || status != 200 {
			return
		}

		type entry struct {
			NameValue string `json:"name_value"`
		}

		var entries []entry
		if err := json.Unmarshal(body, &entries); err != nil {
			return
		}

		seen := make(map[string]struct{})
		for _, e := range entries {
			// name_value can contain multiple newline-separated entries
			for _, line := range strings.Split(e.NameValue, "\n") {
				sub := strings.ToLower(strings.TrimSpace(line))
				sub = strings.TrimPrefix(sub, "*.")
				if sub == "" || strings.Contains(sub, " ") {
					continue
				}
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
