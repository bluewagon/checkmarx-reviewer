package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
)

func setEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CX_APIKEY", "key")
	t.Setenv("CX_BASE_URI", "https://us.ast.checkmarx.net/")
	t.Setenv("CX_TENANT", "acme")
	// Ensure a clean agent selection regardless of the host environment.
	t.Setenv("CX_AI_AGENT", "")
	t.Setenv("CX_AI_MODEL", "")
	t.Setenv("CX_AI_AGENT_BIN", "")
	t.Setenv("CX_AI_BATCH_SIZE", "")
	t.Setenv("CX_AI_COST_LIMIT", "")
	t.Setenv("CX_CONCURRENCY", "")
	t.Setenv("CX_BITBUCKET_TOKEN", "")
	t.Setenv("CX_AI_AGENTIC_SOURCE", "")
	t.Setenv("CX_VERBOSE", "")
	t.Setenv("CX_LOG_DIR", "")
	t.Setenv("CX_SEVERITY", "")
	t.Setenv("CX_RETRIAGE", "")
	t.Setenv("CX_LIMIT", "")
	t.Setenv("CX_STRIP_PATH_PREFIX", "")
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "scan-1", "--repo-path", t.TempDir()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent != ai.AgentClaude {
		t.Errorf("default agent = %q, want %q", cfg.Agent, ai.AgentClaude)
	}
	if cfg.Model != "" {
		t.Errorf("model should default to empty (agent default), got %q", cfg.Model)
	}
	if cfg.FPThreshold != DefaultFPThreshold || cfg.ContextLines != DefaultContextLines {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.BatchSize != DefaultBatchSize {
		t.Errorf("batch size = %d, want %d", cfg.BatchSize, DefaultBatchSize)
	}
	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("concurrency = %d, want %d", cfg.Concurrency, DefaultConcurrency)
	}
	if cfg.CostLimitUSD != DefaultCostLimitUSD {
		t.Errorf("cost limit = %v, want %v (no limit)", cfg.CostLimitUSD, DefaultCostLimitUSD)
	}
	if cfg.AgenticSource {
		t.Errorf("agentic source should default to false")
	}
	if cfg.Verbose {
		t.Errorf("verbose should default to false")
	}
	if cfg.BaseURI != "https://us.ast.checkmarx.net" {
		t.Errorf("trailing slash not trimmed: %q", cfg.BaseURI)
	}
	if len(cfg.Severities) != 1 || cfg.Severities[0] != checkmarx.SeverityHigh {
		t.Errorf("severities = %v, want [HIGH]", cfg.Severities)
	}
}

func TestLoadSeverityFlag(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(),
		"--severity", "critical, HIGH,high,Medium"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{checkmarx.SeverityCritical, checkmarx.SeverityHigh, checkmarx.SeverityMedium}
	if !slices.Equal(cfg.Severities, want) {
		t.Errorf("severities = %v, want %v (normalized, deduped, in input order)", cfg.Severities, want)
	}
}

func TestLoadSeverityEnvDefault(t *testing.T) {
	setEnv(t)
	t.Setenv("CX_SEVERITY", "low")
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(cfg.Severities, []string{checkmarx.SeverityLow}) {
		t.Errorf("severities = %v, want [LOW] from CX_SEVERITY", cfg.Severities)
	}
}

func TestLoadRejectsUnknownSeverity(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--severity", "extreme"})
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("expected severity error, got %v", err)
	}
}

func TestLoadRejectsEmptySeverity(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--severity", " , "})
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("expected severity error, got %v", err)
	}
}

func TestLoadReTriageAndLimitDefaults(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReTriage {
		t.Errorf("re-triage should default to false")
	}
	if cfg.Limit != 0 {
		t.Errorf("limit = %d, want 0 (no limit)", cfg.Limit)
	}
}

func TestLoadReTriageAndLimitFlags(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(),
		"--re-triage", "--limit", "5"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ReTriage {
		t.Errorf("re-triage flag not applied")
	}
	if cfg.Limit != 5 {
		t.Errorf("limit = %d, want 5", cfg.Limit)
	}
}

func TestLoadReTriageAndLimitEnvDefaults(t *testing.T) {
	setEnv(t)
	t.Setenv("CX_RETRIAGE", "true")
	t.Setenv("CX_LIMIT", "3")
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ReTriage {
		t.Errorf("CX_RETRIAGE not applied")
	}
	if cfg.Limit != 3 {
		t.Errorf("limit = %d, want 3 from CX_LIMIT", cfg.Limit)
	}
}

func TestLoadRejectsBadLimit(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--limit", "-1"})
	if err == nil || !strings.Contains(err.Error(), "--limit") {
		t.Fatalf("expected limit error, got %v", err)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	// No env, no flags.
	t.Setenv("CX_APIKEY", "")
	t.Setenv("CX_BASE_URI", "")
	t.Setenv("CX_TENANT", "")
	_, err := Load(nil)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	for _, want := range []string{"--scan-id", "--repo-path", "CX_APIKEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestLoadAcceptsAnthropicAgent(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--agent", "anthropic"})
	if err != nil {
		t.Fatalf("Load with --agent anthropic: %v", err)
	}
	if cfg.Agent != ai.AgentAnthropic {
		t.Errorf("agent = %q, want %q", cfg.Agent, ai.AgentAnthropic)
	}
}

func TestLoadRejectsUnknownAgent(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--agent", "gemini"})
	if err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("expected agent error, got %v", err)
	}
}

func TestLoadRejectsBadBatchSize(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--batch-size", "0"})
	if err == nil || !strings.Contains(err.Error(), "batch-size") {
		t.Fatalf("expected batch-size error, got %v", err)
	}
}

func TestLoadConcurrencyFlag(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--concurrency", "8"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Concurrency != 8 {
		t.Errorf("concurrency = %d, want 8", cfg.Concurrency)
	}
}

func TestLoadRejectsBadConcurrency(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--concurrency", "0"})
	if err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("expected concurrency error, got %v", err)
	}
}

func TestLoadRejectsBadThreshold(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--fp-confidence-threshold", "1.5"})
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

func TestLoadRejectsMissingRepoPath(t *testing.T) {
	setEnv(t)
	_, err := Load([]string{"--scan-id", "s", "--repo-path", "/no/such/dir/really"})
	if err == nil || !strings.Contains(err.Error(), "repo-path") {
		t.Fatalf("expected repo-path error, got %v", err)
	}
}

func TestLoadAcceptsBitbucketURLWithToken(t *testing.T) {
	setEnv(t)
	t.Setenv("CX_BITBUCKET_TOKEN", "tok")
	url := "https://bitbucket.example.com/projects/PROJ/repos/my-repo/browse"
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", url})
	if err != nil {
		t.Fatalf("Load with URL repo-path: %v", err)
	}
	// The URL is kept verbatim; normalization/cloning happens at run time.
	if cfg.RepoPath != url || cfg.BitbucketToken != "tok" {
		t.Errorf("unexpected cfg: repoPath=%q token=%q", cfg.RepoPath, cfg.BitbucketToken)
	}
}

func TestLoadBitbucketTokenFlag(t *testing.T) {
	setEnv(t) // clears CX_BITBUCKET_TOKEN
	url := "https://bitbucket.example.com/scm/PROJ/my-repo.git"
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", url, "--bitbucket-token", "tok"})
	if err != nil {
		t.Fatalf("Load with --bitbucket-token: %v", err)
	}
	// The flag alone satisfies the URL-requires-token rule.
	if cfg.BitbucketToken != "tok" {
		t.Errorf("BitbucketToken = %q, want %q", cfg.BitbucketToken, "tok")
	}
}

func TestLoadBitbucketTokenFlagOverridesEnv(t *testing.T) {
	setEnv(t)
	t.Setenv("CX_BITBUCKET_TOKEN", "env")
	url := "https://bitbucket.example.com/scm/PROJ/my-repo.git"
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", url, "--bitbucket-token", "flag"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BitbucketToken != "flag" {
		t.Errorf("flag should override env: got %q, want %q", cfg.BitbucketToken, "flag")
	}
}

func TestLoadStripPathPrefix(t *testing.T) {
	setEnv(t)
	base := []string{"--scan-id", "s", "--repo-path", t.TempDir()}

	cfg, err := Load(base)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StripPathPrefix != "" {
		t.Errorf("StripPathPrefix should default to empty, got %q", cfg.StripPathPrefix)
	}

	t.Setenv("CX_STRIP_PATH_PREFIX", "/env/sast")
	cfg, err = Load(base)
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.StripPathPrefix != "/env/sast" {
		t.Errorf("StripPathPrefix = %q, want %q from env", cfg.StripPathPrefix, "/env/sast")
	}

	cfg, err = Load(append(base, "--strip-path-prefix", "/flag/sast"))
	if err != nil {
		t.Fatalf("Load with flag: %v", err)
	}
	if cfg.StripPathPrefix != "/flag/sast" {
		t.Errorf("flag should override env: got %q, want %q", cfg.StripPathPrefix, "/flag/sast")
	}
}

func TestLoadAgenticSourceFlag(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--agentic-source"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AgenticSource {
		t.Error("--agentic-source should set AgenticSource true")
	}
}

func TestLoadVerboseFlag(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "s", "--repo-path", t.TempDir(), "--verbose"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Verbose {
		t.Error("--verbose should set Verbose true")
	}
}

func TestLoadLogDir(t *testing.T) {
	setEnv(t)
	base := []string{"--scan-id", "s", "--repo-path", t.TempDir()}

	cfg, err := Load(base)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogDir != DefaultLogDir {
		t.Errorf("default log dir = %q, want %q", cfg.LogDir, DefaultLogDir)
	}

	for _, off := range []string{"off", "OFF"} {
		cfg, err = Load(append(base, "--log-dir", off))
		if err != nil {
			t.Fatalf("Load(--log-dir %s): %v", off, err)
		}
		if cfg.LogDir != "" {
			t.Errorf("--log-dir %s should disable file logging, got %q", off, cfg.LogDir)
		}
	}

	t.Setenv("CX_LOG_DIR", "custom-logs")
	cfg, err = Load(base)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogDir != "custom-logs" {
		t.Errorf("CX_LOG_DIR not honored: got %q", cfg.LogDir)
	}
}

func TestLoadRejectsBitbucketURLWithoutToken(t *testing.T) {
	setEnv(t) // clears CX_BITBUCKET_TOKEN
	url := "https://bitbucket.example.com/scm/PROJ/my-repo.git"
	_, err := Load([]string{"--scan-id", "s", "--repo-path", url})
	if err == nil || !strings.Contains(err.Error(), "CX_BITBUCKET_TOKEN") {
		t.Fatalf("expected CX_BITBUCKET_TOKEN error, got %v", err)
	}
}
