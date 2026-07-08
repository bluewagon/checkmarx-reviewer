package config

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CX_APIKEY", "key")
	t.Setenv("CX_BASE_URI", "https://us.ast.checkmarx.net/")
	t.Setenv("CX_TENANT", "acme")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant")
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t)
	cfg, err := Load([]string{"--scan-id", "scan-1", "--repo-path", t.TempDir()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Model != DefaultModel || cfg.FPThreshold != DefaultFPThreshold || cfg.ContextLines != DefaultContextLines {
		t.Errorf("defaults not applied: %+v", cfg)
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
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err := Load(nil)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	for _, want := range []string{"--scan-id", "--repo-path", "CX_APIKEY", "ANTHROPIC_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
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
