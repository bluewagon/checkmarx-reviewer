// Package vcs turns a Bitbucket (Data Center/Server) repository URL into a local
// checkout: it normalizes the browse/clone URL and shallow-clones it on demand.
package vcs

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// IsRemoteURL reports whether s should be treated as a remote repository URL to
// clone (rather than a path to an existing local checkout).
func IsRemoteURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// NormalizeBitbucketURL converts a Bitbucket DC/Server URL into an HTTP(S) clone
// URL ending in ".git". It accepts either:
//
//   - a clone URL:  https://host[/ctx]/scm/PROJ/repo.git
//   - a browse URL: https://host[/ctx]/projects/PROJ/repos/repo/browse[/...][?at=...]
//     (and the user variant .../users/NAME/repos/repo/browse -> .../scm/~NAME/repo.git)
//
// Any host context path prefix (e.g. "/bitbucket") is preserved. A URL that is
// already in scm form is returned with a ".git" suffix ensured. A URL we don't
// recognize is returned unchanged (best effort).
func NormalizeBitbucketURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parsing repo URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("repo URL %q has no host", raw)
	}

	segs := splitPath(u.Path)

	// Find the /projects/{KEY}/repos/{SLUG}/browse or /users/{NAME}/repos/{SLUG}
	// marker and rebuild the path as {ctx}/scm/{KEY|~NAME}/{SLUG}.git.
	for i := 0; i+3 < len(segs); i++ {
		kind := segs[i]
		if (kind != "projects" && kind != "users") || segs[i+2] != "repos" {
			continue
		}
		owner := segs[i+1]
		slug := segs[i+3]
		if kind == "users" {
			owner = "~" + owner
		}
		ctx := segs[:i] // any context path before /projects or /users
		newPath := "/" + join(append(append([]string{}, ctx...), "scm", owner, ensureGit(slug)))
		return rebuild(u, newPath), nil
	}

	// Already an scm/ clone path: just ensure the .git suffix.
	if slices.Contains(segs, "scm") {
		last := len(segs) - 1
		segs[last] = ensureGit(segs[last])
		return rebuild(u, "/"+join(segs)), nil
	}

	// Unrecognized shape: return as-is.
	return raw, nil
}

// rebuild returns u's scheme://host with the given path and no query/fragment.
func rebuild(u *url.URL, path string) string {
	out := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: path}
	return out.String()
}

// splitPath splits a URL path into non-empty segments.
func splitPath(p string) []string {
	var out []string
	for s := range strings.SplitSeq(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func join(segs []string) string { return strings.Join(segs, "/") }

func ensureGit(slug string) string {
	if strings.HasSuffix(slug, ".git") {
		return slug
	}
	return slug + ".git"
}
