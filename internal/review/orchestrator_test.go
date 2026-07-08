package review

import (
	"context"
	"strings"
	"testing"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/report"
	"github.com/bluewagon/checkmarx-reviewer/internal/source"
)

// --- fakes ---

type postCall struct {
	similarityID, projectID, severity, state, comment string
}

type fakeCx struct {
	scan    *checkmarx.Scan
	results []checkmarx.Result
	history map[string][]checkmarx.Predicate
	posts   []postCall
}

func (f *fakeCx) GetScan(context.Context, string) (*checkmarx.Scan, error) { return f.scan, nil }
func (f *fakeCx) ListHighToVerify(context.Context, string) ([]checkmarx.Result, error) {
	return f.results, nil
}
func (f *fakeCx) GetPredicateHistory(_ context.Context, sim, _ string) ([]checkmarx.Predicate, error) {
	return f.history[sim], nil
}
func (f *fakeCx) PostPredicate(_ context.Context, sim, proj, sev, state, comment string) error {
	f.posts = append(f.posts, postCall{sim, proj, sev, state, comment})
	return nil
}

type fakeReviewer struct{ v ai.Verdict }

func (f fakeReviewer) Review(context.Context, ai.Finding) (ai.Verdict, error) { return f.v, nil }

func result(sim string) checkmarx.Result {
	return checkmarx.Result{
		SimilarityID: sim,
		Severity:     checkmarx.SeverityHigh,
		Data:         checkmarx.ResultData{QueryName: "SQL_Injection", Nodes: []checkmarx.Node{{FileName: "a.go", Line: 1}}},
	}
}

func newOrch(t *testing.T, cx *fakeCx, v ai.Verdict, threshold float64, dryRun bool) *Orchestrator {
	t.Helper()
	return New(cx, fakeReviewer{v}, source.NewReader(t.TempDir(), 2), Options{
		ScanID: "scan-1", Model: "claude-test", FPThreshold: threshold, DryRun: dryRun,
	}, nil)
}

func run(t *testing.T, o *Orchestrator) *report.Report {
	t.Helper()
	rep, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// --- tests ---

func TestHighConfidenceFPSetsProposedNotExploitable(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result("sim-1")}}
	o := newOrch(t, cx, ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.95, Explanation: "sanitized"}, 0.90, false)

	rep := run(t, o)

	if len(cx.posts) != 1 {
		t.Fatalf("expected 1 post, got %d", len(cx.posts))
	}
	p := cx.posts[0]
	if p.state != checkmarx.StateProposedNotExploitable {
		t.Errorf("state = %s, want PROPOSED_NOT_EXPLOITABLE", p.state)
	}
	if !strings.HasPrefix(p.comment, commentMarker) || !strings.Contains(p.comment, "FALSE POSITIVE") {
		t.Errorf("comment missing marker/verdict: %q", p.comment)
	}
	if !strings.Contains(p.comment, "confidence 95%") {
		t.Errorf("comment missing confidence: %q", p.comment)
	}
	if rep.StateChanges != 1 || rep.FalsePositives != 1 || rep.Reviewed != 1 {
		t.Errorf("counters wrong: %+v", rep)
	}
}

func TestLowConfidenceFPCommentsOnly(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result("sim-1")}}
	o := newOrch(t, cx, ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.80, Explanation: "unsure"}, 0.90, false)

	rep := run(t, o)

	if cx.posts[0].state != checkmarx.StateToVerify {
		t.Errorf("state = %s, want TO_VERIFY (below threshold)", cx.posts[0].state)
	}
	if rep.StateChanges != 0 {
		t.Errorf("expected no state changes, got %d", rep.StateChanges)
	}
}

func TestTruePositiveCommentsAndKeepsState(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result("sim-1")}}
	o := newOrch(t, cx, ai.Verdict{Verdict: ai.VerdictTruePositive, Confidence: 0.99, Explanation: "exploitable"}, 0.90, false)

	rep := run(t, o)

	if cx.posts[0].state != checkmarx.StateToVerify {
		t.Errorf("TP should keep TO_VERIFY, got %s", cx.posts[0].state)
	}
	if rep.TruePositives != 1 {
		t.Errorf("expected 1 TP, got %d", rep.TruePositives)
	}
}

func TestSkipsAlreadyReviewed(t *testing.T) {
	cx := &fakeCx{
		scan:    &checkmarx.Scan{ProjectID: "proj-1"},
		results: []checkmarx.Result{result("sim-1")},
		history: map[string][]checkmarx.Predicate{"sim-1": {{Comment: "[AI-REVIEW] TRUE POSITIVE — confidence 90%"}}},
	}
	o := newOrch(t, cx, ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.99}, 0.90, false)

	rep := run(t, o)

	if len(cx.posts) != 0 {
		t.Errorf("expected no posts for already-reviewed finding, got %d", len(cx.posts))
	}
	if rep.Skipped != 1 || rep.Reviewed != 0 {
		t.Errorf("counters wrong: skipped=%d reviewed=%d", rep.Skipped, rep.Reviewed)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result("sim-1")}}
	o := newOrch(t, cx, ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.99, Explanation: "x"}, 0.90, true)

	rep := run(t, o)

	if len(cx.posts) != 0 {
		t.Errorf("dry-run must not post, got %d posts", len(cx.posts))
	}
	// The intended action is still recorded.
	if rep.Findings[0].Action != report.ActionProposedNotExploit || rep.Findings[0].CommentPosted {
		t.Errorf("dry-run finding record wrong: %+v", rep.Findings[0])
	}
}
