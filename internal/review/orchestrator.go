// Package review orchestrates the end-to-end finding review pipeline: fetch
// findings, gather source, ask the AI, and write comments / state changes back.
package review

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/report"
	"github.com/bluewagon/checkmarx-reviewer/internal/source"
)

// commentMarker prefixes every comment we post and is used to detect findings
// we have already reviewed (idempotency).
const commentMarker = "[AI-REVIEW]"

// CheckmarxClient is the subset of the Checkmarx client the orchestrator needs.
// Defined as an interface so the pipeline can be unit-tested with a fake.
type CheckmarxClient interface {
	GetScan(ctx context.Context, scanID string) (*checkmarx.Scan, error)
	ListHighToVerify(ctx context.Context, scanID string) ([]checkmarx.Result, error)
	GetPredicateHistory(ctx context.Context, similarityID, projectID string) ([]checkmarx.Predicate, error)
	PostPredicate(ctx context.Context, similarityID, projectID, severity, state, comment string) error
}

// Options configure a run.
type Options struct {
	ScanID      string
	Agent       string
	Model       string
	FPThreshold float64
	DryRun      bool
}

// Logger is a minimal progress sink (satisfied by log.Printf-style functions).
type Logger func(format string, args ...any)

// Orchestrator wires the collaborators together.
type Orchestrator struct {
	cx   CheckmarxClient
	rev  ai.Reviewer
	src  *source.Reader
	opts Options
	logf Logger
}

// New creates an Orchestrator. logf may be nil.
func New(cx CheckmarxClient, rev ai.Reviewer, src *source.Reader, opts Options, logf Logger) *Orchestrator {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Orchestrator{cx: cx, rev: rev, src: src, opts: opts, logf: logf}
}

// Run executes the pipeline and returns the report. It returns an error only for
// fatal setup failures (auth, scan lookup, results listing); per-finding failures
// are recorded in the report and do not abort the run.
func (o *Orchestrator) Run(ctx context.Context) (*report.Report, error) {
	scan, err := o.cx.GetScan(ctx, o.opts.ScanID)
	if err != nil {
		return nil, fmt.Errorf("fetching scan: %w", err)
	}

	results, err := o.cx.ListHighToVerify(ctx, o.opts.ScanID)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}

	rep := &report.Report{
		ScanID:        o.opts.ScanID,
		ProjectID:     scan.ProjectID,
		Agent:         o.opts.Agent,
		Model:         o.opts.Model,
		FPThreshold:   o.opts.FPThreshold,
		DryRun:        o.opts.DryRun,
		GeneratedAt:   time.Now().UTC(),
		TotalFindings: len(results),
	}

	o.logf("Reviewing %d HIGH/To-Verify findings for scan %s (project %s)", len(results), o.opts.ScanID, scan.ProjectID)

	for i, res := range results {
		o.logf("[%d/%d] %s (%s)", i+1, len(results), res.Data.QueryName, res.SimilarityID)
		fr := o.reviewOne(ctx, scan.ProjectID, res)
		tally(rep, fr)
		rep.Findings = append(rep.Findings, fr)
	}

	return rep, nil
}

// reviewOne processes a single finding, never returning an error (outcomes are
// captured in the FindingResult).
func (o *Orchestrator) reviewOne(ctx context.Context, projectID string, res checkmarx.Result) report.FindingResult {
	fr := report.FindingResult{
		SimilarityID: res.SimilarityID,
		ResultHash:   res.ResultHash,
		QueryName:    res.Data.QueryName,
		Severity:     res.Severity,
		NodesTotal:   len(res.Data.Nodes),
	}
	if sink := sinkNode(res); sink != nil {
		fr.SinkFile = sink.FileName
		fr.SinkLine = sink.Line
	}

	// Idempotency: skip if we've already reviewed this finding.
	history, err := o.cx.GetPredicateHistory(ctx, res.SimilarityID, projectID)
	if err != nil {
		fr.Action = report.ActionError
		fr.Error = fmt.Sprintf("fetching predicate history: %v", err)
		return fr
	}
	if alreadyReviewed(history) {
		fr.Action = report.ActionSkippedAlreadyDone
		return fr
	}

	// Build evidence from source.
	finding, resolved := o.buildFinding(res)
	fr.NodesResolved = resolved

	// Ask the model.
	verdict, err := o.rev.Review(ctx, finding)
	if err != nil {
		fr.Action = report.ActionError
		fr.Error = fmt.Sprintf("ai review: %v", err)
		return fr
	}
	fr.Verdict = verdict.Verdict
	fr.Confidence = verdict.Confidence
	fr.Explanation = verdict.Explanation

	// Decide action.
	state := checkmarx.StateToVerify
	fr.Action = report.ActionCommented
	if verdict.IsFalsePositive() && verdict.Confidence >= o.opts.FPThreshold {
		state = checkmarx.StateProposedNotExploitable
		fr.Action = report.ActionProposedNotExploit
		fr.StateSet = state
	}

	comment := formatComment(verdict, o.opts.Agent, o.opts.Model)

	if o.opts.DryRun {
		return fr
	}

	if err := o.cx.PostPredicate(ctx, res.SimilarityID, projectID, res.Severity, state, comment); err != nil {
		fr.Action = report.ActionError
		fr.StateSet = ""
		fr.Error = fmt.Sprintf("posting predicate: %v", err)
		return fr
	}
	fr.CommentPosted = true
	return fr
}

// buildFinding converts a Checkmarx result plus source snippets into AI evidence,
// returning the number of nodes whose source resolved.
func (o *Orchestrator) buildFinding(res checkmarx.Result) (ai.Finding, int) {
	f := ai.Finding{
		QueryName:   res.Data.QueryName,
		Group:       res.Data.Group,
		Language:    res.Data.LanguageName,
		Severity:    res.Severity,
		Description: res.Description,
	}
	resolved := 0
	for i, n := range res.Data.Nodes {
		snip := o.src.SnippetFor(n.FileName, n.Line)
		nc := ai.NodeContext{
			Order:    i + 1,
			FileName: n.FileName,
			Line:     n.Line,
			Name:     n.Name,
			Method:   n.Method,
			Resolved: snip.Resolved,
		}
		if snip.Resolved {
			nc.Snippet = snip.Code
			resolved++
		} else {
			nc.Snippet = snip.Note
		}
		f.Nodes = append(f.Nodes, nc)
	}
	return f, resolved
}

// sinkNode returns the last node of the data-flow path (the sink), or nil.
func sinkNode(res checkmarx.Result) *checkmarx.Node {
	if len(res.Data.Nodes) == 0 {
		return nil
	}
	return &res.Data.Nodes[len(res.Data.Nodes)-1]
}

// alreadyReviewed reports whether any predicate comment came from this tool.
func alreadyReviewed(history []checkmarx.Predicate) bool {
	for _, p := range history {
		if strings.HasPrefix(strings.TrimSpace(p.Comment), commentMarker) {
			return true
		}
	}
	return false
}

// formatComment renders the comment posted to Checkmarx.
func formatComment(v ai.Verdict, agent, model string) string {
	label := "TRUE POSITIVE"
	if v.IsFalsePositive() {
		label = "FALSE POSITIVE"
	}
	via := agent
	if model != "" {
		via = agent + " (" + model + ")"
	}
	return fmt.Sprintf("%s %s — confidence %d%%\n%s\n—\nvia=%s · reviewed %s · checkmarx-reviewer",
		commentMarker,
		label,
		int(v.Confidence*100+0.5),
		strings.TrimSpace(v.Explanation),
		via,
		time.Now().UTC().Format("2006-01-02"),
	)
}

// tally updates report counters from a finding outcome.
func tally(rep *report.Report, fr report.FindingResult) {
	switch fr.Action {
	case report.ActionSkippedAlreadyDone:
		rep.Skipped++
	case report.ActionError:
		rep.Errors++
	default:
		rep.Reviewed++
		switch fr.Verdict {
		case ai.VerdictTruePositive:
			rep.TruePositives++
		case ai.VerdictFalsePositive:
			rep.FalsePositives++
		}
		if fr.StateSet != "" {
			rep.StateChanges++
		}
	}
}
