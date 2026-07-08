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

func TestBuildUserPromptIncludesEvidence(t *testing.T) {
	f := Finding{
		QueryName: "SQL_Injection",
		Language:  "Go",
		Severity:  "HIGH",
		Nodes: []NodeContext{
			{Order: 1, FileName: "a.go", Line: 10, Name: "req", Method: "Handler", Snippet: "   10| x := req", Resolved: true},
			{Order: 2, FileName: "b.go", Line: 20, Name: "query", Snippet: "file not found", Resolved: false},
		},
	}
	got := buildUserPrompt(f)

	for _, want := range []string{"SQL_Injection", "a.go:10", "b.go:20", "req", "submit_verdict", "source unavailable"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q\n---\n%s", want, got)
		}
	}
}
