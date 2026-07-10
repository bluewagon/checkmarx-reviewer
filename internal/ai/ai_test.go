package ai

import (
	"strings"
	"testing"
)

func TestNormalizeClampsConfidence(t *testing.T) {
	v, err := normalize(Verdict{Verdict: VerdictTruePositive, Confidence: 1.7})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if v.Confidence != 1 {
		t.Errorf("confidence not clamped high: %v", v.Confidence)
	}

	v, err = normalize(Verdict{Verdict: VerdictFalsePositive, Confidence: -0.3})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if v.Confidence != 0 {
		t.Errorf("confidence not clamped low: %v", v.Confidence)
	}
}

func TestNormalizeRejectsUnknownVerdict(t *testing.T) {
	if _, err := normalize(Verdict{Verdict: "MAYBE", Confidence: 0.5}); err == nil {
		t.Fatal("expected error for invalid verdict")
	}
}

func TestIsFalsePositive(t *testing.T) {
	if !(Verdict{Verdict: VerdictFalsePositive}).IsFalsePositive() {
		t.Error("FALSE_POSITIVE should report IsFalsePositive")
	}
	if (Verdict{Verdict: VerdictTruePositive}).IsFalsePositive() {
		t.Error("TRUE_POSITIVE should not report IsFalsePositive")
	}
}

func TestBuildBatchPromptIncludesEvidenceAndIDs(t *testing.T) {
	f1 := Finding{
		ID:        "sim-1",
		QueryName: "SQL_Injection",
		Language:  "Go",
		Severity:  "HIGH",
		Nodes: []NodeContext{
			{Order: 1, FileName: "a.go", Line: 10, Name: "req", Method: "Handler", Snippet: "   10| x := req", Resolved: true, StartLine: 8, EndLine: 12},
			{Order: 2, FileName: "b.go", Line: 20, Name: "query", Snippet: "file not found", Resolved: false},
		},
	}
	f2 := Finding{ID: "sim-2", QueryName: "XSS", Nodes: []NodeContext{{Order: 1, FileName: "c.go", Line: 5, Snippet: "5| out", Resolved: true, StartLine: 3, EndLine: 7}}}

	got := buildBatchPrompt([]Finding{f1, f2}, false)

	for _, want := range []string{"SQL_Injection", "a.go:10", "b.go:20", "req", "id=sim-1", "id=sim-2", "\"id\"", "\"verdict\"", "source unavailable", "2 finding"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q\n---\n%s", want, got)
		}
	}
}

func TestBuildBatchPromptAgenticInvitesRepoAccess(t *testing.T) {
	f := Finding{
		ID:        "sim-1",
		QueryName: "Reflected_XSS",
		Nodes: []NodeContext{{Order: 1, FileName: "page.jsp", Line: 3, Snippet: "   3| <%= data %>", Resolved: true, StartLine: 1, EndLine: 5}},
	}

	agentic := buildBatchPrompt([]Finding{f}, true)

	// Agentic prompt tells the agent it may read/search the repo checkout...
	for _, want := range []string{"working directory", "read-only tools", "Grep"} {
		if !strings.Contains(agentic, want) {
			t.Errorf("agentic prompt missing %q\n---\n%s", want, agentic)
		}
	}
	// ...while still inlining the snippet and finding metadata as a starting point.
	for _, want := range []string{"page.jsp:3", "<%= data %>", "id=sim-1"} {
		if !strings.Contains(agentic, want) {
			t.Errorf("agentic prompt should still include snippet/metadata %q", want)
		}
	}
	// The non-agentic prompt must NOT claim repo access.
	if plain := buildBatchPrompt([]Finding{f}, false); strings.Contains(plain, "read-only tools") {
		t.Errorf("non-agentic prompt should not mention repo tools:\n%s", plain)
	}
}

func TestBuildBatchPromptDedupsCoveredRanges(t *testing.T) {
	// Two nodes in the same file whose ranges are covered by the first; the
	// second must reference rather than reprint the code.
	f := Finding{
		ID:        "sim-1",
		QueryName: "Path_Traversal",
		Nodes: []NodeContext{
			{Order: 1, FileName: "a.go", Line: 10, Snippet: "block-A-source", Resolved: true, StartLine: 5, EndLine: 15},
			{Order: 2, FileName: "a.go", Line: 12, Snippet: "block-A-source", Resolved: true, StartLine: 10, EndLine: 14},
		},
	}
	got := buildBatchPrompt([]Finding{f}, false)

	if strings.Count(got, "block-A-source") != 1 {
		t.Errorf("overlapping snippet should be printed once:\n%s", got)
	}
	if !strings.Contains(got, "code shown above") {
		t.Errorf("expected a reference for the covered node:\n%s", got)
	}
}
