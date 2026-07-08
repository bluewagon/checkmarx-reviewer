// Package config loads and validates runtime configuration from CLI flags and
// environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds all resolved runtime settings for a single review run.
type Config struct {
	// Checkmarx connection (from environment).
	APIKey  string // CX_APIKEY — refresh token
	BaseURI string // CX_BASE_URI — e.g. https://us.ast.checkmarx.net
	Tenant  string // CX_TENANT — tenant name for the auth realm

	// Anthropic (from environment).
	AnthropicAPIKey string // ANTHROPIC_API_KEY

	// Run parameters (from flags).
	ScanID       string
	RepoPath     string
	Model        string
	FPThreshold  float64
	ContextLines int
	ReportPath   string
	DryRun       bool
}

// Defaults for optional settings.
const (
	DefaultModel        = "claude-opus-4-8"
	DefaultFPThreshold  = 0.90
	DefaultContextLines = 8
	DefaultReportPath   = "checkmarx-ai-review.json"
)

// Load parses flags from args (excluding the program name) and reads the
// required environment variables, returning a validated Config.
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("checkmarx-reviewer", flag.ContinueOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.ScanID, "scan-id", "", "Checkmarx scan ID to review (required)")
	fs.StringVar(&cfg.RepoPath, "repo-path", "", "Path to a local checkout matching the scanned commit (required)")
	fs.StringVar(&cfg.Model, "model", envOr("CX_AI_MODEL", DefaultModel), "Claude model ID")
	fs.Float64Var(&cfg.FPThreshold, "fp-confidence-threshold", DefaultFPThreshold, "Minimum confidence [0-1] to auto-set Proposed Not Exploitable")
	fs.IntVar(&cfg.ContextLines, "context-lines", DefaultContextLines, "Source lines of context to include around each data-flow node")
	fs.StringVar(&cfg.ReportPath, "report", DefaultReportPath, "Path to write the JSON report")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Compute verdicts and intended actions without writing to Checkmarx")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.APIKey = os.Getenv("CX_APIKEY")
	cfg.BaseURI = strings.TrimRight(os.Getenv("CX_BASE_URI"), "/")
	cfg.Tenant = os.Getenv("CX_TENANT")
	cfg.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var missing []string
	if c.ScanID == "" {
		missing = append(missing, "--scan-id")
	}
	if c.RepoPath == "" {
		missing = append(missing, "--repo-path")
	}
	if c.APIKey == "" {
		missing = append(missing, "CX_APIKEY")
	}
	if c.BaseURI == "" {
		missing = append(missing, "CX_BASE_URI")
	}
	if c.Tenant == "" {
		missing = append(missing, "CX_TENANT")
	}
	if c.AnthropicAPIKey == "" {
		missing = append(missing, "ANTHROPIC_API_KEY")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	if c.FPThreshold < 0 || c.FPThreshold > 1 {
		return errors.New("--fp-confidence-threshold must be between 0 and 1")
	}
	if c.ContextLines < 0 {
		return errors.New("--context-lines must be >= 0")
	}

	info, err := os.Stat(c.RepoPath)
	if err != nil {
		return fmt.Errorf("--repo-path %q is not accessible: %w", c.RepoPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--repo-path %q is not a directory", c.RepoPath)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
