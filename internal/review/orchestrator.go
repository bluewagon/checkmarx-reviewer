// Package review orchestrates the end-to-end finding review pipeline: fetch
// findings, gather source, ask the AI, and write comments / state changes back.
package review

import (
	"context"
	"fmt"
	"strconv"
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
	ScanID       string
	Agent        string
	Model        string
	BatchSize    int
	FPThreshold  float64
	CostLimitUSD float64 // stop the run once cumulative AI cost exceeds this (0 = no limit)
	DryRun       bool
}

// Logger is a minimal progress sink (satisfied by log.Printf-style functions).
type Logger func(format string, args ...any)

// Orchestrator wires the collaborators together.
type Orchestrator struct {
	cx    CheckmarxClient
	rev   ai.Reviewer
	src   *source.Reader
	opts  Options
	logf  Logger
	spent ai.Usage // cumulative token/cost usage across all AI calls this run
}

// New creates an Orchestrator. logf may be nil.
func New(cx CheckmarxClient, rev ai.Reviewer, src *source.Reader, opts Options, logf Logger) *Orchestrator {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Orchestrator{cx: cx, rev: rev, src: src, opts: opts, logf: logf}
}

// recordUsage accumulates one AI call's usage into the run total and logs it.
func (o *Orchestrator) recordUsage(u ai.Usage) {
	if u == (ai.Usage{}) {
		return // agent reported no usage (e.g. Copilot, or a failed call)
	}
	o.spent.Add(u)
	o.logf("AI call: +$%.4f (in=%d out=%d cache=%d) — run total $%.4f, %d tokens",
		u.CostUSD, u.InputTokens, u.OutputTokens,
		u.CacheCreationInputTokens+u.CacheReadInputTokens,
		o.spent.CostUSD, o.spent.TotalTokens())
}

// overBudget reports whether the cumulative cost has reached the configured
// limit. A limit of 0 (or less) disables the check.
func (o *Orchestrator) overBudget() bool {
	return o.opts.CostLimitUSD > 0 && o.spent.CostUSD >= o.opts.CostLimitUSD
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
		BatchSize:     o.opts.BatchSize,
		FPThreshold:   o.opts.FPThreshold,
		DryRun:        o.opts.DryRun,
		GeneratedAt:   time.Now().UTC(),
		TotalFindings: len(results),
	}

	o.logf("Reviewing %d HIGH/To-Verify findings for scan %s (project %s), batch size %d",
		len(results), o.opts.ScanID, scan.ProjectID, o.opts.BatchSize)

	// Phase 1: prepare each finding (idempotency check + source evidence).
	items := make([]*item, len(results))
	for i, res := range results {
		items[i] = o.prepare(ctx, scan.ProjectID, res)
	}

	// Phase 2: review non-terminal findings in bounded batches, with per-finding
	// fallback for anything a batch fails to answer. Stops early on cost limit.
	aborted := o.reviewBatches(ctx, items)

	// Phase 3: act on verdicts and assemble the report (original order preserved).
	for _, it := range items {
		if !it.terminal && it.hasVerdict {
			o.applyVerdict(ctx, it)
		}
		tally(rep, it.fr)
		rep.Findings = append(rep.Findings, it.fr)
	}

	// Record token/cost totals and any cost-limit abort on the report.
	rep.CostLimitUSD = o.opts.CostLimitUSD
	rep.EstimatedCostUSD = o.spent.CostUSD
	rep.InputTokens = o.spent.InputTokens
	rep.OutputTokens = o.spent.OutputTokens
	rep.TotalTokens = o.spent.TotalTokens()
	if aborted {
		rep.Aborted = true
		rep.AbortReason = fmt.Sprintf("cost limit $%.2f reached (spent $%.4f)", o.opts.CostLimitUSD, o.spent.CostUSD)
	}

	return rep, nil
}

// item is the per-finding working state threaded through the pipeline phases.
type item struct {
	res        checkmarx.Result
	projectID  string
	finding    ai.Finding
	fr         report.FindingResult
	verdict    ai.Verdict
	hasVerdict bool
	terminal   bool // skipped or errored before/without AI review
}

// prepare runs the idempotency check and builds source evidence for one finding.
func (o *Orchestrator) prepare(ctx context.Context, projectID string, res checkmarx.Result) *item {
	it := &item{res: res, projectID: projectID}
	simID := strconv.FormatInt(res.SimilarityID, 10)
	it.fr = report.FindingResult{
		SimilarityID: simID,
		ResultHash:   res.ResultHash,
		QueryName:    res.Data.QueryName,
		Severity:     res.Severity,
		NodesTotal:   len(res.Data.Nodes),
	}
	if sink := sinkNode(res); sink != nil {
		it.fr.SinkFile = sink.FileName
		it.fr.SinkLine = sink.Line
	}

	history, err := o.cx.GetPredicateHistory(ctx, simID, projectID)
	if err != nil {
		it.fr.Action = report.ActionError
		it.fr.Error = fmt.Sprintf("fetching predicate history: %v", err)
		it.terminal = true
		return it
	}
	if alreadyReviewed(history) {
		it.fr.Action = report.ActionSkippedAlreadyDone
		it.terminal = true
		return it
	}

	finding, resolved := o.buildFinding(res)
	it.finding = finding
	it.fr.NodesResolved = resolved
	return it
}

// reviewBatches chunks the non-terminal items and reviews each batch. It stops
// early once the cost limit is exceeded, marking any not-yet-reviewed findings as
// budget-skipped, and reports whether it aborted for that reason.
func (o *Orchestrator) reviewBatches(ctx context.Context, items []*item) bool {
	var pending []*item
	for _, it := range items {
		if !it.terminal {
			pending = append(pending, it)
		}
	}
	if len(pending) == 0 {
		return false
	}

	size := max(o.opts.BatchSize, 1)

	batchNum := 0
	for start := 0; start < len(pending); start += size {
		end := min(start+size, len(pending))
		batchNum++
		o.logf("Reviewing batch %d (%d finding(s))", batchNum, end-start)
		o.reviewBatch(ctx, pending[start:end])

		if o.overBudget() {
			o.logf("Cost limit reached ($%.4f >= $%.2f); stopping. %d finding(s) left unreviewed.",
				o.spent.CostUSD, o.opts.CostLimitUSD, len(pending)-end)
			markBudgetSkipped(pending[end:])
			return true
		}
	}
	return false
}

// markBudgetSkipped records findings left unreviewed because the cost limit was
// hit, so they appear in the report rather than silently disappearing.
func markBudgetSkipped(items []*item) {
	for _, it := range items {
		if it.terminal || it.hasVerdict {
			continue
		}
		it.fr.Action = report.ActionSkippedBudget
		it.terminal = true
	}
}

// reviewBatch reviews one batch in a single agent call, falling back to
// individual review for any finding the batch does not answer.
func (o *Orchestrator) reviewBatch(ctx context.Context, batch []*item) {
	findings := make([]ai.Finding, len(batch))
	byID := make(map[string]*item, len(batch))
	for i, it := range batch {
		findings[i] = it.finding
		byID[it.finding.ID] = it
	}

	verdicts, usage, err := o.rev.Review(ctx, findings)
	o.recordUsage(usage)
	if err != nil {
		o.logf("batch review failed (%v); falling back to individual review", err)
		for _, it := range batch {
			o.reviewIndividually(ctx, it)
		}
		return
	}

	for id, v := range verdicts {
		if it, ok := byID[id]; ok {
			it.verdict = v
			it.hasVerdict = true
		}
	}
	for _, it := range batch {
		if !it.hasVerdict {
			o.reviewIndividually(ctx, it)
		}
	}
}

// reviewIndividually re-reviews a single finding (batch of one). On failure the
// finding is marked terminal with an ERROR outcome.
func (o *Orchestrator) reviewIndividually(ctx context.Context, it *item) {
	verdicts, usage, err := o.rev.Review(ctx, []ai.Finding{it.finding})
	o.recordUsage(usage)
	if err != nil {
		it.fr.Action = report.ActionError
		it.fr.Error = fmt.Sprintf("ai review: %v", err)
		it.terminal = true
		return
	}
	v, ok := verdicts[it.finding.ID]
	if !ok {
		it.fr.Action = report.ActionError
		it.fr.Error = "agent did not return a valid verdict for this finding"
		it.terminal = true
		return
	}
	it.verdict = v
	it.hasVerdict = true
}

// applyVerdict decides the action for a reviewed finding and writes it back.
func (o *Orchestrator) applyVerdict(ctx context.Context, it *item) {
	v := it.verdict
	it.fr.Verdict = v.Verdict
	it.fr.Confidence = v.Confidence
	it.fr.Explanation = v.Explanation

	state := checkmarx.StateToVerify
	it.fr.Action = report.ActionCommented
	if v.IsFalsePositive() && v.Confidence >= o.opts.FPThreshold {
		state = checkmarx.StateProposedNotExploitable
		it.fr.Action = report.ActionProposedNotExploit
		it.fr.StateSet = state
	}

	comment := formatComment(v, o.opts.Agent, o.opts.Model)

	if o.opts.DryRun {
		return
	}

	if err := o.cx.PostPredicate(ctx, strconv.FormatInt(it.res.SimilarityID, 10), it.projectID, it.res.Severity, state, comment); err != nil {
		it.fr.Action = report.ActionError
		it.fr.StateSet = ""
		it.fr.Error = fmt.Sprintf("posting predicate: %v", err)
		return
	}
	it.fr.CommentPosted = true
}

// buildFinding converts a Checkmarx result plus source snippets into AI evidence,
// returning the number of nodes whose source resolved.
func (o *Orchestrator) buildFinding(res checkmarx.Result) (ai.Finding, int) {
	f := ai.Finding{
		ID:          strconv.FormatInt(res.SimilarityID, 10),
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
			nc.StartLine = snip.StartLine
			nc.EndLine = snip.EndLine
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
	case report.ActionSkippedAlreadyDone, report.ActionSkippedBudget:
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
