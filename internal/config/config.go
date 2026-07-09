// Package config loads and validates runtime configuration from CLI flags and
// environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
)

// Config holds all resolved runtime settings for a single review run.
type Config struct {
	// Checkmarx connection (from environment).
	APIKey  string // CX_APIKEY — refresh token
	BaseURI string // CX_BASE_URI — e.g. https://us.ast.checkmarx.net
	Tenant  string // CX_TENANT — tenant name for the auth realm

	// Run parameters (from flags).
	ScanID       string
	RepoPath     string
	Agent        string // "claude" or "copilot"
	AgentBin     string // optional override of the agent binary name/path
	Model        string // agent model id (may be empty to use agent default)
	AgentTimeout time.Duration
	BatchSize    int // findings reviewed per agent invocation
	FPThreshold  float64
	CostLimitUSD float64 // stop the run once cumulative AI cost (USD) exceeds this; 0 = no limit
	ContextLines int
	ReportPath   string
	DryRun       bool
}

// Defaults for optional settings.
const (
	DefaultAgent          = ai.AgentClaude
	DefaultFPThreshold    = 0.90
	DefaultCostLimitUSD   = 0 // 0 = no cost limit
	DefaultContextLines   = 8
	DefaultReportPath     = "checkmarx-ai-review.json"
	DefaultTimeoutSeconds = 300
	DefaultBatchSize      = 10
)

// Load parses flags from args (excluding the program name) and reads the
// required environment variables, returning a validated Config.
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("checkmarx-reviewer", flag.ContinueOnError)

	var timeoutSeconds int
	cfg := &Config{}
	fs.StringVar(&cfg.ScanID, "scan-id", "", "Checkmarx scan ID to review (required)")
	fs.StringVar(&cfg.RepoPath, "repo-path", "", "Path to a local checkout matching the scanned commit (required)")
	fs.StringVar(&cfg.Agent, "agent", envOr("CX_AI_AGENT", DefaultAgent), "AI agent CLI to use: "+strings.Join(ai.SupportedAgents(), " | "))
	fs.StringVar(&cfg.AgentBin, "agent-bin", os.Getenv("CX_AI_AGENT_BIN"), "Override the agent binary name/path (default: the agent's own command)")
	fs.StringVar(&cfg.Model, "model", os.Getenv("CX_AI_MODEL"), "Model id to pass to the agent (default: the agent's default)")
	fs.IntVar(&timeoutSeconds, "agent-timeout", DefaultTimeoutSeconds, "Per-invocation agent timeout, in seconds")
	fs.IntVar(&cfg.BatchSize, "batch-size", envIntOr("CX_AI_BATCH_SIZE", DefaultBatchSize), "Findings reviewed per agent invocation (>=1); higher saves tokens")
	fs.Float64Var(&cfg.FPThreshold, "fp-confidence-threshold", DefaultFPThreshold, "Minimum confidence [0-1] to auto-set Proposed Not Exploitable")
	fs.Float64Var(&cfg.CostLimitUSD, "cost-limit", envFloatOr("CX_AI_COST_LIMIT", DefaultCostLimitUSD), "Stop the run once cumulative AI cost (USD) exceeds this; 0 = no limit (only enforced for the Claude agent, which reports cost)")
	fs.IntVar(&cfg.ContextLines, "context-lines", DefaultContextLines, "Source lines of context to include around each data-flow node")
	fs.StringVar(&cfg.ReportPath, "report", DefaultReportPath, "Path to write the JSON report")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Compute verdicts and intended actions without writing to Checkmarx")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.Agent = strings.ToLower(strings.TrimSpace(cfg.Agent))
	cfg.AgentTimeout = time.Duration(timeoutSeconds) * time.Second
	cfg.APIKey = os.Getenv("CX_APIKEY")
	cfg.BaseURI = strings.TrimRight(os.Getenv("CX_BASE_URI"), "/")
	cfg.Tenant = os.Getenv("CX_TENANT")

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
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	if !slices.Contains(ai.SupportedAgents(), c.Agent) {
		return fmt.Errorf("--agent %q is not supported (choose one of: %s)", c.Agent, strings.Join(ai.SupportedAgents(), ", "))
	}
	if c.FPThreshold < 0 || c.FPThreshold > 1 {
		return errors.New("--fp-confidence-threshold must be between 0 and 1")
	}
	if c.CostLimitUSD < 0 {
		return errors.New("--cost-limit must be >= 0")
	}
	if c.ContextLines < 0 {
		return errors.New("--context-lines must be >= 0")
	}
	if c.AgentTimeout <= 0 {
		return errors.New("--agent-timeout must be > 0")
	}
	if c.BatchSize < 1 {
		return errors.New("--batch-size must be >= 1")
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

// envIntOr returns the integer value of an env var, or fallback if unset/invalid.
func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// envFloatOr returns the float value of an env var, or fallback if unset/invalid.
func envFloatOr(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}
