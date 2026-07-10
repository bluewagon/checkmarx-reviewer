package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	postErr error // when set, PostPredicate returns it instead of succeeding
}

func (f *fakeCx) GetScan(context.Context, string) (*checkmarx.Scan, error) { return f.scan, nil }
func (f *fakeCx) ListHighToVerify(context.Context, string) ([]checkmarx.Result, error) {
	return f.results, nil
}
func (f *fakeCx) GetPredicateHistory(_ context.Context, sim, _ string) ([]checkmarx.Predicate, error) {
	return f.history[sim], nil
}
func (f *fakeCx) PostPredicate(_ context.Context, sim, proj, sev, state, comment string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.posts = append(f.posts, postCall{sim, proj, sev, state, comment})
	return nil
}

// fakeReviewer returns f.v for each finding in a batch, keyed by id. It can
// simulate dropped findings and batch-level failures for fallback testing.
type fakeReviewer struct {
	v               ai.Verdict
	usagePerCall    ai.Usage        // usage returned by each Review call
	batchSizes      []int           // recorded size of each Review call
	omitAlways      map[string]bool // never answer these ids
	omitInBatch     map[string]bool // omit only when batch size > 1 (answered on fallback)
	errIfLargerThan int             // return an error when batch size exceeds this (0 = never)
}

func (f *fakeReviewer) Review(_ context.Context, findings []ai.Finding) (map[string]ai.Verdict, ai.Usage, error) {
	f.batchSizes = append(f.batchSizes, len(findings))
	if f.errIfLargerThan > 0 && len(findings) > f.errIfLargerThan {
		return nil, f.usagePerCall, fmt.Errorf("simulated batch failure")
	}
	out := make(map[string]ai.Verdict, len(findings))
	for _, fnd := range findings {
		if f.omitAlways[fnd.ID] {
			continue
		}
		if len(findings) > 1 && f.omitInBatch[fnd.ID] {
			continue
		}
		v := f.v
		v.ID = fnd.ID
		out[fnd.ID] = v
	}
	return out, f.usagePerCall, nil
}

func result(sim int64) checkmarx.Result {
	return checkmarx.Result{
		SimilarityID: checkmarx.SimilarityID(sim),
		Severity:     checkmarx.SeverityHigh,
		Data:         checkmarx.ResultData{QueryName: "SQL_Injection", Nodes: []checkmarx.Node{{FileName: "a.go", Line: 1}}},
	}
}

func newOrch(t *testing.T, cx *fakeCx, v ai.Verdict, threshold float64, dryRun bool) *Orchestrator {
	t.Helper()
	return newOrchRev(t, cx, &fakeReviewer{v: v}, threshold, dryRun, 10)
}

func newOrchRev(t *testing.T, cx *fakeCx, rev ai.Reviewer, threshold float64, dryRun bool, batchSize int) *Orchestrator {
	t.Helper()
	return New(cx, rev, source.NewReader(t.TempDir(), 2), Options{
		ScanID: "scan-1", Model: "claude-test", BatchSize: batchSize, FPThreshold: threshold, DryRun: dryRun,
	}, nil)
}

func results(sims ...int64) []checkmarx.Result {
	rs := make([]checkmarx.Result, len(sims))
	for i, s := range sims {
		rs[i] = result(s)
	}
	return rs
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
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result(1)}}
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
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result(1)}}
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
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result(1)}}
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
		results: []checkmarx.Result{result(1)},
		history: map[string][]checkmarx.Predicate{"1": {{Comment: "[AI-REVIEW] TRUE POSITIVE — confidence 90%"}}},
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
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: []checkmarx.Result{result(1)}}
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

func TestBatchingChunksBySizeAndPreservesOrder(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: results(1, 2, 3, 4, 5)}
	rev := &fakeReviewer{v: ai.Verdict{Verdict: ai.VerdictTruePositive, Confidence: 0.9, Explanation: "x"}}
	o := newOrchRev(t, cx, rev, 0.90, false, 2)

	rep := run(t, o)

	if want := []int{2, 2, 1}; fmt.Sprint(rev.batchSizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v", rev.batchSizes, want)
	}
	if len(cx.posts) != 5 || rep.Reviewed != 5 {
		t.Errorf("expected 5 reviewed/posted, got posts=%d reviewed=%d", len(cx.posts), rep.Reviewed)
	}
	for i, want := range []string{"1", "2", "3", "4", "5"} {
		if rep.Findings[i].SimilarityID != want {
			t.Errorf("report order[%d] = %s, want %s", i, rep.Findings[i].SimilarityID, want)
		}
	}
}

func TestFallbackReReviewsFindingDroppedFromBatch(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: results(1, 2, 3)}
	// finding 2 is dropped in the multi-finding batch but answered on individual retry.
	rev := &fakeReviewer{
		v:           ai.Verdict{Verdict: ai.VerdictTruePositive, Confidence: 0.9, Explanation: "x"},
		omitInBatch: map[string]bool{"2": true},
	}
	o := newOrchRev(t, cx, rev, 0.90, false, 3)

	rep := run(t, o)

	if rep.Reviewed != 3 || rep.Errors != 0 {
		t.Fatalf("expected all 3 reviewed via fallback, got reviewed=%d errors=%d", rep.Reviewed, rep.Errors)
	}
	// One batch of 3, then one fallback of 1 for finding 2.
	if want := []int{3, 1}; fmt.Sprint(rev.batchSizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v", rev.batchSizes, want)
	}
	if len(cx.posts) != 3 {
		t.Errorf("expected 3 posts, got %d", len(cx.posts))
	}
}

func TestFallbackExhaustedMarksError(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: results(1, 2)}
	// finding 2 is never answered, even individually.
	rev := &fakeReviewer{
		v:          ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.99, Explanation: "x"},
		omitAlways: map[string]bool{"2": true},
	}
	o := newOrchRev(t, cx, rev, 0.90, false, 2)

	rep := run(t, o)

	if rep.Errors != 1 || rep.Reviewed != 1 {
		t.Fatalf("expected 1 error + 1 reviewed, got errors=%d reviewed=%d", rep.Errors, rep.Reviewed)
	}
	// Only finding 1 should have been posted.
	if len(cx.posts) != 1 || cx.posts[0].similarityID != "1" {
		t.Errorf("expected only finding 1 posted, got %+v", cx.posts)
	}
	var sim2 *report.FindingResult
	for i := range rep.Findings {
		if rep.Findings[i].SimilarityID == "2" {
			sim2 = &rep.Findings[i]
		}
	}
	if sim2 == nil || sim2.Action != report.ActionError {
		t.Errorf("finding 2 should be ERROR, got %+v", sim2)
	}
}

func TestCostLimitStopsRunAndMarksRemaining(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: results(1, 2, 3, 4, 5)}
	// Each call costs $0.05; with a $0.10 limit the run stops after two batches.
	rev := &fakeReviewer{
		v:            ai.Verdict{Verdict: ai.VerdictTruePositive, Confidence: 0.9, Explanation: "x"},
		usagePerCall: ai.Usage{InputTokens: 100, OutputTokens: 20, CostUSD: 0.05},
	}
	o := New(cx, rev, source.NewReader(t.TempDir(), 2), Options{
		ScanID: "scan-1", Model: "claude-test", BatchSize: 1, FPThreshold: 0.90, CostLimitUSD: 0.10,
	}, nil)

	rep := run(t, o)

	if !rep.Aborted {
		t.Errorf("expected run to be aborted on cost limit")
	}
	if rep.Reviewed != 2 || rep.Skipped != 3 {
		t.Errorf("expected reviewed=2 skipped=3, got reviewed=%d skipped=%d", rep.Reviewed, rep.Skipped)
	}
	if len(cx.posts) != 2 {
		t.Errorf("expected only 2 posts before the limit, got %d", len(cx.posts))
	}
	if rep.EstimatedCostUSD != 0.10 {
		t.Errorf("estimated cost = %v, want 0.10", rep.EstimatedCostUSD)
	}
	if rep.TotalTokens != 240 { // 2 calls * (100 + 20)
		t.Errorf("total tokens = %d, want 240", rep.TotalTokens)
	}
	// The three findings after the limit must be recorded as budget-skipped.
	skipped := 0
	for _, fr := range rep.Findings {
		if fr.Action == report.ActionSkippedBudget {
			skipped++
		}
	}
	if skipped != 3 {
		t.Errorf("expected 3 SKIPPED_COST_LIMIT findings, got %d", skipped)
	}
}

func TestPerFindingErrorIsLoggedLive(t *testing.T) {
	cx := &fakeCx{
		scan:    &checkmarx.Scan{ProjectID: "proj-1"},
		results: results(1),
		postErr: errors.New("boom-503"),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	o := New(cx, &fakeReviewer{v: ai.Verdict{Verdict: ai.VerdictFalsePositive, Confidence: 0.99, Explanation: "x"}},
		source.NewReader(t.TempDir(), 2),
		Options{ScanID: "scan-1", Model: "claude-test", BatchSize: 10, FPThreshold: 0.90},
		logger)

	rep := run(t, o)

	if rep.Errors != 1 {
		t.Fatalf("expected 1 error, got %d", rep.Errors)
	}
	// The failure must be surfaced live with context, not just counted.
	out := buf.String()
	if !strings.Contains(out, "posting predicate failed") {
		t.Errorf("log missing the failure message:\n%s", out)
	}
	if !strings.Contains(out, "similarityId=1") {
		t.Errorf("log missing the finding id context:\n%s", out)
	}
	if !strings.Contains(out, "boom-503") {
		t.Errorf("log missing the underlying cause:\n%s", out)
	}
}

func TestBatchInvocationErrorFallsBackToIndividual(t *testing.T) {
	cx := &fakeCx{scan: &checkmarx.Scan{ProjectID: "proj-1"}, results: results(1, 2)}
	// Any batch larger than 1 fails; individual retries succeed.
	rev := &fakeReviewer{
		v:               ai.Verdict{Verdict: ai.VerdictTruePositive, Confidence: 0.9, Explanation: "x"},
		errIfLargerThan: 1,
	}
	o := newOrchRev(t, cx, rev, 0.90, false, 2)

	rep := run(t, o)

	if rep.Reviewed != 2 || rep.Errors != 0 {
		t.Fatalf("expected 2 reviewed via individual fallback, got reviewed=%d errors=%d", rep.Reviewed, rep.Errors)
	}
	if want := []int{2, 1, 1}; fmt.Sprint(rev.batchSizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v (failed batch then two singles)", rev.batchSizes, want)
	}
}
