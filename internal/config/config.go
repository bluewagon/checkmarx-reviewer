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
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/vcs"
	"github.com/joho/godotenv"
)

// Config holds all resolved runtime settings for a single review run.
type Config struct {
	// Checkmarx connection (from environment).
	APIKey  string // CX_APIKEY — refresh token
	BaseURI string // CX_BASE_URI — e.g. https://us.ast.checkmarx.net
	Tenant  string // CX_TENANT — tenant name for the auth realm

	// Bitbucket (from environment). Used only when --repo-path is a Bitbucket URL.
	BitbucketToken string // CX_BITBUCKET_TOKEN — HTTP access token for cloning

	// Run parameters (from flags).
	ScanID       string
	Severities   []string // severities of TO_VERIFY findings to triage (normalized to uppercase)
	RepoPath     string
	Agent        string // "claude" or "copilot"
	AgentBin     string // optional override of the agent binary name/path
	Model        string // agent model id (may be empty to use agent default)
	AgentTimeout time.Duration
	BatchSize    int // findings reviewed per agent invocation
	Concurrency  int // max findings/batches processed in parallel (1 = sequential)
	FPThreshold  float64
	CostLimitUSD float64 // stop the run once cumulative AI cost (USD) exceeds this; 0 = no limit
	ContextLines int
	ReportPath   string
	// ReTriage re-reviews findings already triaged by this tool instead of
	// skipping them.
	ReTriage bool
	// Limit caps how many findings are reviewed this run (0 = no limit). New
	// findings are selected before re-triaged ones.
	Limit  int
	DryRun bool
	// AgenticSource lets the agent read/search the repo for extra context instead
	// of relying only on the inlined snippets.
	AgenticSource bool
	// Verbose enables debug-level logging (HTTP requests, agent invocations, full
	// error causes).
	Verbose bool
	// LogDir is the directory for per-run JSONL debug logs and raw API/prompt
	// dumps. Empty disables file logging.
	LogDir string
}

// Defaults for optional settings.
const (
	DefaultAgent          = ai.AgentClaude
	DefaultSeverity       = checkmarx.SeverityHigh
	DefaultFPThreshold    = 0.90
	DefaultCostLimitUSD   = 0 // 0 = no cost limit
	DefaultContextLines   = 8
	DefaultReportPath     = "checkmarx-ai-review.json"
	DefaultTimeoutSeconds = 600 // sized for batch 20, incl. agentic repo exploration
	DefaultBatchSize      = 20
	DefaultConcurrency    = 4
	DefaultLogDir         = "logs"
)

// Load parses flags from args (excluding the program name) and reads the
// required environment variables, returning a validated Config.
func Load(args []string) (*Config, error) {
	_ = godotenv.Load()
	fs := flag.NewFlagSet("checkmarx-reviewer", flag.ContinueOnError)

	var timeoutSeconds int
	var severities string
	cfg := &Config{}
	fs.StringVar(&cfg.ScanID, "scan-id", "", "Checkmarx scan ID to review (required)")
	fs.StringVar(&severities, "severity", envOr("CX_SEVERITY", DefaultSeverity),
		"Comma-separated severities of To-Verify findings to triage: "+strings.Join(checkmarx.Severities(), " | "))
	fs.StringVar(&cfg.RepoPath, "repo-path", "", "Local checkout matching the scanned commit, or a Bitbucket clone/browse URL to shallow-clone (required)")
	fs.StringVar(&cfg.Agent, "agent", envOr("CX_AI_AGENT", DefaultAgent), "AI agent CLI to use: "+strings.Join(ai.SupportedAgents(), " | "))
	fs.StringVar(&cfg.AgentBin, "agent-bin", os.Getenv("CX_AI_AGENT_BIN"), "Override the agent binary name/path (default: the agent's own command; ignored for the anthropic API agent)")
	fs.StringVar(&cfg.Model, "model", os.Getenv("CX_AI_MODEL"), "Model id to pass to the agent (default: the agent's default)")
	fs.IntVar(&timeoutSeconds, "agent-timeout", DefaultTimeoutSeconds, "Per-invocation agent timeout, in seconds")
	fs.IntVar(&cfg.BatchSize, "batch-size", envIntOr("CX_AI_BATCH_SIZE", DefaultBatchSize), "Findings reviewed per agent invocation (>=1); higher saves tokens")
	fs.IntVar(&cfg.Concurrency, "concurrency", envIntOr("CX_CONCURRENCY", DefaultConcurrency), "Max findings/batches processed in parallel (history fetches, agent calls, predicate posts); 1 = fully sequential")
	fs.Float64Var(&cfg.FPThreshold, "fp-confidence-threshold", DefaultFPThreshold, "Minimum confidence [0-1] to auto-set Proposed Not Exploitable")
	fs.Float64Var(&cfg.CostLimitUSD, "cost-limit", envFloatOr("CX_AI_COST_LIMIT", DefaultCostLimitUSD), "Stop the run once cumulative AI cost (USD) exceeds this; 0 = no limit (enforced for agents that report cost: the claude CLI and the anthropic API agent)")
	fs.IntVar(&cfg.ContextLines, "context-lines", DefaultContextLines, "Source lines of context to include around each data-flow node")
	fs.StringVar(&cfg.ReportPath, "report", DefaultReportPath, "Path to write the JSON report")
	fs.BoolVar(&cfg.ReTriage, "re-triage", envBoolOr("CX_RETRIAGE", false), "Re-review findings already triaged by this tool (overrides the already-reviewed skip)")
	fs.IntVar(&cfg.Limit, "limit", envIntOr("CX_LIMIT", 0), "Maximum findings to review this run (0 = no limit); new findings are selected before re-triaged ones")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Compute verdicts and intended actions without writing to Checkmarx")
	fs.BoolVar(&cfg.AgenticSource, "agentic-source", envBoolOr("CX_AI_AGENTIC_SOURCE", false), "Let the agent read/search the repo for extra context instead of only the inlined snippets (uses more time per finding)")
	fs.BoolVar(&cfg.Verbose, "verbose", envBoolOr("CX_VERBOSE", false), "Enable debug logging (HTTP requests, agent invocations, full error causes)")
	fs.StringVar(&cfg.LogDir, "log-dir", envOr("CX_LOG_DIR", DefaultLogDir), "Directory for per-run JSONL debug logs and raw API/prompt dumps (\"off\" disables)")
	fs.StringVar(&cfg.BitbucketToken, "bitbucket-token", os.Getenv("CX_BITBUCKET_TOKEN"), "Bitbucket HTTP access token for cloning a Bitbucket --repo-path URL (default: $CX_BITBUCKET_TOKEN)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.Agent = strings.ToLower(strings.TrimSpace(cfg.Agent))
	sevs, err := parseSeverities(severities)
	if err != nil {
		return nil, err
	}
	cfg.Severities = sevs
	cfg.AgentTimeout = time.Duration(timeoutSeconds) * time.Second
	// "off" is the explicit disable keyword: an empty CX_LOG_DIR reads as unset
	// (envOr falls back to the default), so empty can't be the off switch.
	if strings.EqualFold(strings.TrimSpace(cfg.LogDir), "off") {
		cfg.LogDir = ""
	}
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
	if c.Concurrency < 1 {
		return errors.New("--concurrency must be >= 1")
	}
	if c.Limit < 0 {
		return errors.New("--limit must be >= 0")
	}

	// A Bitbucket URL is cloned at runtime, so it needn't exist locally, but it
	// does require an access token to authenticate the clone.
	if vcs.IsRemoteURL(c.RepoPath) {
		if c.BitbucketToken == "" {
			return errors.New("--repo-path is a URL but no Bitbucket token was provided (set --bitbucket-token or CX_BITBUCKET_TOKEN)")
		}
		return nil
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

// parseSeverities normalizes a comma-separated severity list to the uppercase
// values the API uses, rejecting unknown values and deduplicating repeats.
func parseSeverities(s string) ([]string, error) {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		sev := strings.ToUpper(strings.TrimSpace(part))
		if sev == "" {
			continue
		}
		if !slices.Contains(checkmarx.Severities(), sev) {
			return nil, fmt.Errorf("--severity %q is not valid (choose from: %s)", part, strings.Join(checkmarx.Severities(), ", "))
		}
		if !slices.Contains(out, sev) {
			out = append(out, sev)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--severity must name at least one severity")
	}
	return out, nil
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

// envBoolOr returns the bool value of an env var, or fallback if unset/invalid.
func envBoolOr(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
