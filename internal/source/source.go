// Package source reads code from a local repository checkout to provide the AI
// reviewer with the real source context around each data-flow node.
package source

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Reader reads snippets from a repository rooted at RepoRoot.
type Reader struct {
	RepoRoot     string
	ContextLines int
}

// NewReader creates a Reader.
func NewReader(repoRoot string, contextLines int) *Reader {
	return &Reader{RepoRoot: repoRoot, ContextLines: contextLines}
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

	f, err := os.Open(full)
	if err != nil {
		s.Note = fmt.Sprintf("file not found under repo root: %s", rel)
		return s
	}
	defer f.Close()

	start := max(line-r.ContextLines, 1)
	end := line + r.ContextLines

	var b strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n := 0
	for scanner.Scan() {
		n++
		if n < start {
			continue
		}
		if n > end {
			break
		}
		marker := "   "
		if n == line {
			marker = ">> "
		}
		fmt.Fprintf(&b, "%s%5d| %s\n", marker, n, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		s.Note = fmt.Sprintf("error reading file: %v", err)
		return s
	}
	if n < line {
		s.Note = fmt.Sprintf("file has only %d lines; node line %d out of range", n, line)
		return s
	}

	s.StartLine = start
	s.EndLine = min(end, n) // clamp to EOF
	s.Code = strings.TrimRight(b.String(), "\n")
	s.Resolved = true
	return s
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
