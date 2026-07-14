// Package source reads code from a local repository checkout to provide the AI
// reviewer with the real source context around each data-flow node.
package source

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Snippet is the resolved source context for a single data-flow node.
type Snippet struct {
	FileName  string // node file path, as reported by Checkmarx
	Line      int    // the node's line (1-based)
	StartLine int    // first line included in Code
	EndLine   int    // last line included in Code (clamped at EOF)
	Code      string // numbered source lines, or empty if unresolved
	Resolved  bool   // whether the file was found and read
	Note      string // reason it was not resolved, if applicable
}

// maxCachedFiles caps how many files the Reader keeps in memory. Findings on a
// large scan cluster in a few hundred files; beyond the cap files are read
// without being cached so memory stays bounded on very large repos.
const maxCachedFiles = 512

// Reader reads snippets from a repository rooted at RepoRoot. File contents are
// cached after the first read, since many findings reference the same files.
// Safe for concurrent use.
type Reader struct {
	RepoRoot     string
	ContextLines int

	mu    sync.Mutex
	cache map[string][]string // file lines keyed by resolved path
}

// NewReader creates a Reader.
func NewReader(repoRoot string, contextLines int) *Reader {
	return &Reader{RepoRoot: repoRoot, ContextLines: contextLines, cache: make(map[string][]string)}
}

// SnippetFor reads the source lines around a node's line, including
// r.ContextLines lines of context on each side. A missing or unreadable file is
// reported via Resolved=false and Note rather than as an error, so a single bad
// path does not abort a review run.
func (r *Reader) SnippetFor(fileName string, line int) Snippet {
	s := Snippet{FileName: fileName, Line: line}

	rel := strings.TrimLeft(filepath.FromSlash(fileName), string(filepath.Separator))
	full := filepath.Join(r.RepoRoot, rel)

	// Guard against path traversal escaping the repo root.
	if !within(r.RepoRoot, full) {
		s.Note = "path resolves outside repo root"
		return s
	}

	lines, err := r.fileLines(full)
	if err != nil {
		s.Note = fmt.Sprintf("file not found under repo root: %s", rel)
		return s
	}
	if len(lines) < line {
		s.Note = fmt.Sprintf("file has only %d lines; node line %d out of range", len(lines), line)
		return s
	}

	start := max(line-r.ContextLines, 1)
	end := min(line+r.ContextLines, len(lines)) // clamp to EOF

	var b strings.Builder
	for n := start; n <= end; n++ {
		marker := "   "
		if n == line {
			marker = ">> "
		}
		fmt.Fprintf(&b, "%s%5d| %s\n", marker, n, lines[n-1])
	}

	s.StartLine = start
	s.EndLine = end
	s.Code = strings.TrimRight(b.String(), "\n")
	s.Resolved = true
	return s
}

// fileLines returns the file's lines, serving repeats from the cache. Beyond
// maxCachedFiles entries new files are read but not retained.
func (r *Reader) fileLines(path string) ([]string, error) {
	r.mu.Lock()
	if lines, ok := r.cache[path]; ok {
		r.mu.Unlock()
		return lines, nil
	}
	r.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Split keeps prior scanner semantics: an empty file has zero lines and a
	// trailing newline does not create a phantom final line.
	var lines []string
	if len(data) > 0 {
		text := strings.TrimSuffix(string(data), "\n")
		text = strings.TrimSuffix(text, "\r")
		lines = strings.Split(text, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimSuffix(l, "\r")
		}
	}

	r.mu.Lock()
	if len(r.cache) < maxCachedFiles {
		r.cache[path] = lines
	}
	r.mu.Unlock()
	return lines, nil
}

// within reports whether target is inside root (or equal to it).
func within(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
