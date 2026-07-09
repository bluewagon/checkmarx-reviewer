package config

import (
	"strings"
	"testing"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
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
	if cfg.CostLimitUSD != DefaultCostLimitUSD {
		t.Errorf("cost limit = %v, want %v (no limit)", cfg.CostLimitUSD, DefaultCostLimitUSD)
	}
	if cfg.BaseURI != "https://us.ast.checkmarx.net" {
		t.Errorf("trailing slash not trimmed: %q", cfg.BaseURI)
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
