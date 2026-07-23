package review

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/report"
)

// PredicatePoster is the single Checkmarx capability the resume path needs:
// writing a triage predicate. Satisfied by *checkmarx.Client.
type PredicatePoster interface {
	PostPredicate(ctx context.Context, similarityID, projectID, severity, state, comment string) error
}

// ResumeOptions configure a resume run.
type ResumeOptions struct {
	Concurrency int  // max posts in flight (<=1 = sequential)
	DryRun      bool // log intended posts without writing to Checkmarx
}

// ResumeSummary reports what a resume run did.
type ResumeSummary struct {
	Candidates       int // findings eligible to re-post (verdict present, not posted)
	Reposted         int // successfully (re)posted this run
	Failed           int // still failed to post
	NoVerdictSkipped int // unposted findings with no verdict — need a full review re-run
}

// resumable reports whether a finding can be re-posted purely from the report: it
// carries a computed verdict but was never successfully posted, having either
// errored during posting or been cut short when the run was cancelled mid-posting.
func resumable(fr report.FindingResult) bool {
	if fr.Verdict == "" || fr.CommentPosted {
		return false
	}
	switch fr.Action {
	case report.ActionSkippedCancelled:
		return true
	case report.ActionError:
		return strings.HasPrefix(fr.Error, "posting predicate")
	default:
		return false
	}
}

// Resume re-posts the predicates for findings that hold a verdict but were never
// posted (post failures or a run cancelled mid-posting), rebuilding each state and
// comment from the saved report — no AI calls or scan listing. It mutates rep in
// place (flipping successful posts to their reviewed action and re-tallying the
// summary counters) and returns a summary. It stops posting on context
// cancellation, leaving the rest untouched for a later resume.
func Resume(ctx context.Context, cx PredicatePoster, rep *report.Report, opts ResumeOptions, log *slog.Logger) ResumeSummary {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	var candidates []int
	summary := ResumeSummary{}
	for i := range rep.Findings {
		fr := rep.Findings[i]
		if resumable(fr) {
			candidates = append(candidates, i)
			continue
		}
		// An unposted finding with no verdict can't be resumed from the report; it
		// needs a full review re-run.
		if fr.Verdict == "" && !fr.CommentPosted &&
			(fr.Action == report.ActionSkippedCancelled || fr.Action == report.ActionError) {
			summary.NoVerdictSkipped++
		}
	}
	summary.Candidates = len(candidates)

	log.Info("resume: re-posting predicates", "candidates", summary.Candidates,
		"noVerdictSkipped", summary.NoVerdictSkipped, "projectId", rep.ProjectID,
		"scanId", rep.ScanID, "dryRun", opts.DryRun)

	if len(candidates) == 0 {
		return summary
	}

	prog := newProgress(log, "resume: posting", len(candidates))
	var mu sync.Mutex // guards summary counters and cancelled flag
	cancelled := false
	runConcurrent(max(opts.Concurrency, 1), len(candidates), func(k int) {
		mu.Lock()
		stop := cancelled
		mu.Unlock()
		if stop {
			return
		}
		if ctx.Err() != nil {
			mu.Lock()
			cancelled = true
			mu.Unlock()
			return
		}

		fr := &rep.Findings[candidates[k]]
		v := ai.Verdict{
			ID:            fr.SimilarityID,
			Verdict:       fr.Verdict,
			Confidence:    fr.Confidence,
			Explanation:   fr.Explanation,
			AgenticSource: fr.AgenticSource,
		}
		state, action := decideState(v, rep.FPThreshold)
		comment := formatComment(v)

		if opts.DryRun {
			log.Info("dry run: would post predicate",
				"similarityId", fr.SimilarityID, "projectId", rep.ProjectID,
				"query", fr.QueryName, "severity", fr.Severity, "state", state,
				"comment", comment)
			prog.record(false)
			return
		}

		if err := cx.PostPredicate(ctx, fr.SimilarityID, rep.ProjectID, fr.Severity, state, comment); err != nil {
			log.Error("resume: posting predicate failed", "similarityId", fr.SimilarityID,
				"query", fr.QueryName, "state", state, "err", err)
			fr.Action = report.ActionError
			fr.StateSet = ""
			fr.CommentPosted = false
			fr.Error = fmt.Sprintf("posting predicate: %v", err)
			mu.Lock()
			summary.Failed++
			mu.Unlock()
			prog.record(true)
			return
		}

		fr.Action = action
		fr.StateSet = ""
		if state == checkmarx.StateProposedNotExploitable {
			fr.StateSet = state
		}
		fr.CommentPosted = true
		fr.Error = ""
		mu.Lock()
		summary.Reposted++
		mu.Unlock()
		log.Debug("resume: predicate posted", "similarityId", fr.SimilarityID,
			"query", fr.QueryName, "state", state)
		prog.record(false)
	})

	if opts.DryRun {
		return summary
	}

	// Re-tally the run counters from scratch so the rewritten report stays
	// internally consistent (a resumed cancelled finding moves from skipped to
	// reviewed), then refresh the timestamp and abort state.
	retally(rep)
	rep.GeneratedAt = time.Now().UTC()
	if summary.Failed > 0 {
		rep.Aborted = true
		rep.AbortReason = fmt.Sprintf("%d finding(s) still failed to post after resume", summary.Failed)
	} else {
		rep.Aborted = false
		rep.AbortReason = ""
	}

	return summary
}

// retally recomputes the top-level outcome counters from the current finding
// actions, reusing tally so resume and the review pipeline stay in agreement.
func retally(rep *report.Report) {
	rep.Reviewed = 0
	rep.Skipped = 0
	rep.Errors = 0
	rep.TruePositives = 0
	rep.FalsePositives = 0
	rep.StateChanges = 0
	for _, fr := range rep.Findings {
		tally(rep, fr)
	}
}
