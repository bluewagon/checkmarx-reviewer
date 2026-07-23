package review

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/report"
)

// fakePoster records predicate posts and can be made to fail.
type fakePoster struct {
	postErr error

	mu    sync.Mutex
	posts []postCall
}

func (f *fakePoster) PostPredicate(_ context.Context, sim, proj, sev, state, comment string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.mu.Lock()
	f.posts = append(f.posts, postCall{sim, proj, sev, state, comment})
	f.mu.Unlock()
	return nil
}

// baseReport returns a report holding the four canonical finding kinds resume
// must discriminate between.
func baseReport() *report.Report {
	return &report.Report{
		ScanID:      "scan-1",
		ProjectID:   "proj-1",
		FPThreshold: 0.90,
		Findings: []report.FindingResult{
			{ // post failure — resumable
				SimilarityID: "sim-postfail",
				QueryName:    "SQL_Injection",
				Severity:     checkmarx.SeverityHigh,
				Verdict:      ai.VerdictTruePositive,
				Confidence:   0.8,
				Explanation:  "reachable sink",
				Action:       report.ActionError,
				Error:        "posting predicate: 502 bad gateway",
			},
			{ // cancelled mid-posting, verdict present — resumable
				SimilarityID: "sim-cancelled",
				QueryName:    "XSS",
				Severity:     checkmarx.SeverityHigh,
				Verdict:      ai.VerdictFalsePositive,
				Confidence:   0.95,
				Explanation:  "output encoded",
				Action:       report.ActionSkippedCancelled,
			},
			{ // already posted — untouched
				SimilarityID:  "sim-done",
				QueryName:     "Path_Traversal",
				Severity:      checkmarx.SeverityHigh,
				Verdict:       ai.VerdictTruePositive,
				Confidence:    0.7,
				Action:        report.ActionCommented,
				CommentPosted: true,
			},
			{ // AI-review error, no verdict — not resumable
				SimilarityID: "sim-noverdict",
				QueryName:    "Command_Injection",
				Severity:     checkmarx.SeverityHigh,
				Action:       report.ActionError,
				Error:        "ai review: agent timeout",
			},
		},
	}
}

func TestResumeRepostsFailedAndCancelled(t *testing.T) {
	rep := baseReport()
	cx := &fakePoster{}

	summary := Resume(context.Background(), cx, rep, ResumeOptions{Concurrency: 1}, nil)

	if summary.Candidates != 2 {
		t.Fatalf("candidates = %d, want 2", summary.Candidates)
	}
	if summary.Reposted != 2 {
		t.Fatalf("reposted = %d, want 2", summary.Reposted)
	}
	if summary.Failed != 0 {
		t.Fatalf("failed = %d, want 0", summary.Failed)
	}
	if summary.NoVerdictSkipped != 1 {
		t.Fatalf("noVerdictSkipped = %d, want 1", summary.NoVerdictSkipped)
	}
	if len(cx.posts) != 2 {
		t.Fatalf("posts = %d, want 2", len(cx.posts))
	}

	// The true-positive post failure re-posts as a plain comment (state unchanged).
	pf := findingBySim(rep, "sim-postfail")
	if pf.Action != report.ActionCommented || !pf.CommentPosted || pf.StateSet != "" || pf.Error != "" {
		t.Fatalf("post-fail finding not resolved as comment: %+v", pf)
	}

	// The high-confidence false positive re-posts as Proposed Not Exploitable.
	c := findingBySim(rep, "sim-cancelled")
	if c.Action != report.ActionProposedNotExploit || !c.CommentPosted ||
		c.StateSet != checkmarx.StateProposedNotExploitable {
		t.Fatalf("cancelled finding not resolved as proposed-NE: %+v", c)
	}

	// The already-posted and no-verdict findings are untouched.
	if d := findingBySim(rep, "sim-done"); d.Action != report.ActionCommented {
		t.Fatalf("already-posted finding changed: %+v", d)
	}
	if nv := findingBySim(rep, "sim-noverdict"); nv.CommentPosted || nv.Action != report.ActionError {
		t.Fatalf("no-verdict finding changed: %+v", nv)
	}

	// Counters re-tallied over all findings: 3 reviewed (post-fail comment +
	// cancelled proposed-NE + the already-posted sim-done), 2 TP (post-fail +
	// sim-done), 1 FP (cancelled), 1 state change, 1 error (no-verdict), 0 skipped.
	if rep.Reviewed != 3 || rep.TruePositives != 2 || rep.FalsePositives != 1 ||
		rep.StateChanges != 1 || rep.Errors != 1 || rep.Skipped != 0 {
		t.Fatalf("retally wrong: reviewed=%d tp=%d fp=%d state=%d err=%d skip=%d",
			rep.Reviewed, rep.TruePositives, rep.FalsePositives, rep.StateChanges,
			rep.Errors, rep.Skipped)
	}
	if rep.Aborted {
		t.Fatalf("report marked aborted despite no failures")
	}
}

func TestResumePostFailureKeepsError(t *testing.T) {
	rep := baseReport()
	cx := &fakePoster{postErr: errors.New("still down")}

	summary := Resume(context.Background(), cx, rep, ResumeOptions{Concurrency: 1}, nil)

	if summary.Reposted != 0 || summary.Failed != 2 {
		t.Fatalf("reposted=%d failed=%d, want 0/2", summary.Reposted, summary.Failed)
	}
	pf := findingBySim(rep, "sim-postfail")
	if pf.Action != report.ActionError || pf.CommentPosted {
		t.Fatalf("post-fail finding should stay errored: %+v", pf)
	}
	if pf.Error == "" {
		t.Fatalf("post-fail finding should carry a fresh error")
	}
	if !rep.Aborted || rep.AbortReason == "" {
		t.Fatalf("report should be marked aborted on remaining failures")
	}
}

func TestResumeDryRunPostsNothing(t *testing.T) {
	rep := baseReport()
	before := findingBySim(rep, "sim-postfail").Action
	cx := &fakePoster{}

	summary := Resume(context.Background(), cx, rep, ResumeOptions{Concurrency: 1, DryRun: true}, nil)

	if len(cx.posts) != 0 {
		t.Fatalf("dry run posted %d predicates, want 0", len(cx.posts))
	}
	if summary.Candidates != 2 {
		t.Fatalf("candidates = %d, want 2", summary.Candidates)
	}
	if got := findingBySim(rep, "sim-postfail").Action; got != before {
		t.Fatalf("dry run mutated finding action: %q -> %q", before, got)
	}
}

func findingBySim(rep *report.Report, sim string) report.FindingResult {
	for _, fr := range rep.Findings {
		if fr.SimilarityID == sim {
			return fr
		}
	}
	return report.FindingResult{}
}
