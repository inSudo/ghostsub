package httpclient

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

// Client is a resilient HTTP client with retry, backoff, jitter, and UA rotation.
type Client struct {
	inner      *http.Client
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
}

// New creates a Client with sensible defaults.
func New(timeout time.Duration, maxRetries int) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
	}

	return &Client{
		inner: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		maxRetries: maxRetries,
		baseDelay:  1 * time.Second,
		maxDelay:   30 * time.Second,
	}
}

// Get performs a GET request with retry/backoff/UA rotation.
// Handles: timeout, 429, 5xx, network errors, context cancellation.
func (c *Client) Get(ctx context.Context, url string) ([]byte, int, error) {
	var lastErr error

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		// Check context before each attempt
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", randomUA())
		req.Header.Set("Accept", "application/json, text/html, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Connection", "keep-alive")

		resp, err := c.inner.Do(req)
		if err != nil {
			// Network error — check if context was cancelled
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			lastErr = fmt.Errorf("attempt %d: network error: %w", attempt+1, err)
			c.sleep(ctx, attempt)
			continue
		}

		statusCode := resp.StatusCode

		// 429 Too Many Requests — respect Retry-After
		if statusCode == 429 {
			waitDur := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			if ctx.Err() != nil {
				return nil, 429, ctx.Err()
			}
			select {
			case <-ctx.Done():
				return nil, 429, ctx.Err()
			case <-time.After(waitDur):
			}
			lastErr = fmt.Errorf("attempt %d: rate limited (429)", attempt+1)
			continue
		}

		// 5xx — retry with backoff
		if statusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("attempt %d: server error %d", attempt+1, statusCode)
			c.sleep(ctx, attempt)
			continue
		}

		// 403/404 — no point retrying
		if statusCode == 403 || statusCode == 404 {
			resp.Body.Close()
			return nil, statusCode, fmt.Errorf("http %d: %s", statusCode, url)
		}

		// Success — read body
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: read body: %w", attempt+1, err)
			c.sleep(ctx, attempt)
			continue
		}

		return body, statusCode, nil
	}

	return nil, 0, fmt.Errorf("max retries (%d) exceeded: %w", c.maxRetries, lastErr)
}

// GetWithHeaders performs GET with custom headers.
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	var lastErr error

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", randomUA())
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.inner.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			lastErr = err
			c.sleep(ctx, attempt)
			continue
		}

		if resp.StatusCode == 429 {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, 429, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error %d", resp.StatusCode)
			c.sleep(ctx, attempt)
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			c.sleep(ctx, attempt)
			continue
		}

		return body, resp.StatusCode, nil
	}

	return nil, 0, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// PostForm performs a POST with form data.
func (c *Client) PostForm(ctx context.Context, url string, data map[string]string, headers map[string]string) ([]byte, int, error) {
	var lastErr error

	formParts := []string{}
	for k, v := range data {
		formParts = append(formParts, k+"="+v)
	}
	body := strings.Join(formParts, "&")

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", randomUA())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.inner.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			lastErr = err
			c.sleep(ctx, attempt)
			continue
		}

		if resp.StatusCode == 429 {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, 429, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error %d", resp.StatusCode)
			c.sleep(ctx, attempt)
			continue
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			c.sleep(ctx, attempt)
			continue
		}

		return respBody, resp.StatusCode, nil
	}

	return nil, 0, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) sleep(ctx context.Context, attempt int) {
	delay := c.baseDelay * time.Duration(1<<uint(attempt))
	if delay > c.maxDelay {
		delay = c.maxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay / 2)))
	total := delay + jitter

	select {
	case <-ctx.Done():
	case <-time.After(total):
	}
}

func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 5 * time.Second
	}
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil {
		return 5 * time.Second
	}
	if secs > 120 {
		secs = 120 // cap at 2 minutes
	}
	return time.Duration(secs) * time.Second
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}
