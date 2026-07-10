package vcs

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// withFakeRunner swaps the package runner for the duration of a test.
func withFakeRunner(t *testing.T, fn runner) {
	t.Helper()
	orig := run
	run = fn
	t.Cleanup(func() { run = orig })
}

func TestCloneShallowArgsAndBearerEnv(t *testing.T) {
	var gotArgs, gotEnv []string
	withFakeRunner(t, func(_ context.Context, args, env []string) error {
		gotArgs, gotEnv = args, env
		return nil
	})

	const url = "https://bitbucket.example.com/scm/PROJ/my-repo.git"
	const token = "secret-token-123"
	if err := Clone(context.Background(), url, token, "/tmp/dest"); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// Shallow clone args, with the URL and destination present.
	for _, want := range []string{"clone", "--depth", "1", url, "/tmp/dest"} {
		if !slices.Contains(gotArgs, want) {
			t.Errorf("args %v missing %q", gotArgs, want)
		}
	}
	// The token must never appear in argv.
	if slices.ContainsFunc(gotArgs, func(a string) bool { return strings.Contains(a, token) }) {
		t.Errorf("token leaked into args: %v", gotArgs)
	}

	// Bearer header injected via GIT_CONFIG_*, scoped to scheme+host.
	assertEnv(t, gotEnv, "GIT_CONFIG_COUNT", "1")
	assertEnv(t, gotEnv, "GIT_CONFIG_KEY_0", "http.https://bitbucket.example.com/.extraHeader")
	assertEnv(t, gotEnv, "GIT_CONFIG_VALUE_0", "Authorization: Bearer "+token)
}

func TestCloneNoTokenOmitsHeader(t *testing.T) {
	var gotEnv []string
	withFakeRunner(t, func(_ context.Context, _, env []string) error {
		gotEnv = env
		return nil
	})

	if err := Clone(context.Background(), "https://host/scm/p/r.git", "", "/tmp/dest"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	for _, e := range gotEnv {
		if strings.HasPrefix(e, "GIT_CONFIG_") {
			t.Errorf("no GIT_CONFIG_* expected without a token, got %q", e)
		}
	}
}

func assertEnv(t *testing.T, env []string, key, want string) {
	t.Helper()
	prefix := key + "="
	for _, e := range env {
		if got, ok := strings.CutPrefix(e, prefix); ok {
			if got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
			return
		}
	}
	t.Errorf("env missing %s (want %q)", key, want)
}
