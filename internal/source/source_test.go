package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSnippetForResolvesAndMarksLine(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "src/app.go", "l1\nl2\nl3\nl4\nl5\nl6\nl7\n")
	r := NewReader(root, 2)

	s := r.SnippetFor("src/app.go", 4)
	if !s.Resolved {
		t.Fatalf("expected resolved, note=%q", s.Note)
	}
	if s.StartLine != 2 {
		t.Errorf("StartLine = %d, want 2", s.StartLine)
	}
	if !strings.Contains(s.Code, ">> ") || !strings.Contains(s.Code, "l4") {
		t.Errorf("expected marked line 4 in code:\n%s", s.Code)
	}
	// Context window: lines 2..6 present, line 1 and 7 absent.
	if strings.Contains(s.Code, "l1") || strings.Contains(s.Code, "l7") {
		t.Errorf("context window wrong:\n%s", s.Code)
	}
}

func TestSnippetForClampsAtStart(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "one\ntwo\nthree\n")
	r := NewReader(root, 5)
	s := r.SnippetFor("a.go", 1)
	if !s.Resolved || s.StartLine != 1 {
		t.Fatalf("StartLine = %d resolved=%v", s.StartLine, s.Resolved)
	}
}

func TestSnippetForMissingFile(t *testing.T) {
	r := NewReader(t.TempDir(), 2)
	s := r.SnippetFor("does/not/exist.go", 3)
	if s.Resolved {
		t.Fatal("expected unresolved for missing file")
	}
	if s.Note == "" {
		t.Error("expected a note explaining the miss")
	}
}

func TestSnippetForLineOutOfRange(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "one\ntwo\n")
	r := NewReader(root, 2)
	s := r.SnippetFor("a.go", 99)
	if s.Resolved {
		t.Fatal("expected unresolved when line beyond EOF")
	}
}

func TestSnippetForRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	r := NewReader(root, 2)
	s := r.SnippetFor("../../../etc/passwd", 1)
	if s.Resolved {
		t.Fatal("expected path traversal to be rejected")
	}
}
