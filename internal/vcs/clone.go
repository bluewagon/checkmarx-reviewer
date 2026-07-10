package vcs

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// runner executes a git command with an environment; abstracted so tests can
// inject a fake and assert on args/env without shelling out.
type runner func(ctx context.Context, args, env []string) error

// execRunner is the production runner backed by os/exec.
func execRunner(ctx context.Context, args, env []string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// run is the runner used by Clone; overridable in tests.
var run runner = execRunner

// Clone shallow-clones cloneURL into dir with `git clone --depth 1`. When token
// is non-empty it is sent as an `Authorization: Bearer <token>` HTTP header,
// injected via git's GIT_CONFIG_* environment variables so the token never
// appears in the process argument list. The header is scoped to the clone URL's
// scheme+host so it is not sent on a redirect to a different host.
func Clone(ctx context.Context, cloneURL, token, dir string) error {
	args := []string{"clone", "--depth", "1", cloneURL, dir}

	env := os.Environ()
	if token != "" {
		key, err := extraHeaderKey(cloneURL)
		if err != nil {
			return err
		}
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0="+key,
			"GIT_CONFIG_VALUE_0=Authorization: Bearer "+token,
		)
	}

	if err := run(ctx, args, env); err != nil {
		return err
	}
	return nil
}

// CloneToTemp shallow-clones cloneURL into a fresh temp directory, returning the
// directory and a cleanup func that removes it. On error the temp dir is removed
// and cleanup is a no-op.
func CloneToTemp(ctx context.Context, cloneURL, token string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "cxreview-repo-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating temp dir: %w", err)
	}
	if err := Clone(ctx, cloneURL, token, dir); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}

// extraHeaderKey builds the host-scoped git config key
// `http.<scheme>://<host>/.extraHeader` for cloneURL.
func extraHeaderKey(cloneURL string) (string, error) {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return "", fmt.Errorf("parsing clone URL %q: %w", cloneURL, err)
	}
	return fmt.Sprintf("http.%s://%s/.extraHeader", u.Scheme, u.Host), nil
}
