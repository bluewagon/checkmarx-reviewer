package vcs

import "testing"

func TestIsRemoteURL(t *testing.T) {
	cases := map[string]bool{
		"https://bitbucket.example.com/scm/p/r.git": true,
		"http://bitbucket.example.com/x":             true,
		"  https://host/x  ":                         true, // surrounding space tolerated
		"./repo":                                     false,
		"/abs/path/to/repo":                          false,
		"repo":                                       false,
		"git@bitbucket.example.com:p/r.git":          false, // ssh not handled here
	}
	for in, want := range cases {
		if got := IsRemoteURL(in); got != want {
			t.Errorf("IsRemoteURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeBitbucketURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "browse URL",
			in:   "https://bitbucket.example.com/projects/PROJ/repos/my-repo/browse",
			want: "https://bitbucket.example.com/scm/PROJ/my-repo.git",
		},
		{
			name: "browse URL with sub-path and ?at ref",
			in:   "https://bitbucket.example.com/projects/PROJ/repos/my-repo/browse/src/main.go?at=refs%2Fheads%2Fmain",
			want: "https://bitbucket.example.com/scm/PROJ/my-repo.git",
		},
		{
			name: "user repo browse URL",
			in:   "https://bitbucket.example.com/users/jdoe/repos/my-repo/browse",
			want: "https://bitbucket.example.com/scm/~jdoe/my-repo.git",
		},
		{
			name: "already a clone URL",
			in:   "https://bitbucket.example.com/scm/PROJ/my-repo.git",
			want: "https://bitbucket.example.com/scm/PROJ/my-repo.git",
		},
		{
			name: "clone URL missing .git suffix",
			in:   "https://bitbucket.example.com/scm/PROJ/my-repo",
			want: "https://bitbucket.example.com/scm/PROJ/my-repo.git",
		},
		{
			name: "context path preserved on browse URL",
			in:   "https://host.example.com/bitbucket/projects/PROJ/repos/my-repo/browse",
			want: "https://host.example.com/bitbucket/scm/PROJ/my-repo.git",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeBitbucketURL(tc.in)
			if err != nil {
				t.Fatalf("NormalizeBitbucketURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeBitbucketURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeBitbucketURLErrors(t *testing.T) {
	if _, err := NormalizeBitbucketURL("https://"); err == nil {
		t.Error("expected error for URL with no host")
	}
}
