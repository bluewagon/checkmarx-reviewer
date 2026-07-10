package checkmarx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is a minimal Checkmarx One REST client. It exchanges an API key
// (refresh token) for short-lived access tokens and caches them until expiry.
type Client struct {
	baseURI string
	tenant  string
	apiKey  string

	http *http.Client
	log  *slog.Logger

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// Options configure a Client. HTTPClient and Logger are optional.
type Options struct {
	BaseURI    string
	Tenant     string
	APIKey     string
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// New creates a Client. BaseURI should have no trailing slash.
func New(opts Options) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		baseURI: strings.TrimRight(opts.BaseURI, "/"),
		tenant:  opts.Tenant,
		apiKey:  opts.APIKey,
		http:    hc,
		log:     logger,
	}
}

// tokenResponse is the OIDC token endpoint payload.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// accessToken returns a valid bearer token, refreshing if needed.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp) {
		c.log.Debug("using cached access token")
		return c.token, nil
	}

	c.log.Debug("exchanging refresh token for access token", "tenant", c.tenant)
	endpoint := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", c.baseURI, c.tenant)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "ast-app")
	form.Set("refresh_token", c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token response contained no access_token")
	}

	c.token = tr.AccessToken
	// Refresh 30s before actual expiry to avoid edge-of-window failures.
	lifetime := time.Duration(tr.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = 5 * time.Minute
	}
	c.tokenExp = time.Now().Add(lifetime - 30*time.Second)
	return c.token, nil
}

// doJSON performs an authenticated request and decodes a JSON response into out
// (which may be nil to ignore the body). method/path are joined onto baseURI;
// path should begin with "/api". query may be nil.
func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	u := c.baseURI + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	c.log.Debug("checkmarx request", "method", method, "path", path)
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		c.log.Error("checkmarx request errored", "method", method, "path", path, "err", err)
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	c.log.Debug("checkmarx response", "method", method, "path", path,
		"status", resp.StatusCode, "duration", time.Since(start))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.log.Warn("checkmarx request failed", "method", method, "path", path,
			"status", resp.StatusCode, "body", truncate(string(respBody), 1000))
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		c.log.Error("decoding response failed", "method", method, "path", path,
			"body", truncate(string(respBody), 1000), "err", err)
		return fmt.Errorf("decoding %s %s response: %w", method, path, err)
	}
	return nil
}

// truncate trims s to at most n characters, appending an ellipsis if cut.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
