// Package review orchestrates the end-to-end finding review pipeline: fetch
// findings, gather source, ask the AI, and write comments / state changes back.
package review

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
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
	ListToVerify(ctx context.Context, scanID string, severities []string) ([]checkmarx.Result, error)
	GetPredicateHistory(ctx context.Context, similarityID, projectID string) ([]checkmarx.Predicate, error)
	PostPredicate(ctx context.Context, similarityID, projectID, severity, state, comment string) error
}

// Options configure a run.
type Options struct {
	ScanID       string
	Severities   []string // severities of TO_VERIFY findings to triage
	Agent        string
	Model        string
	BatchSize    int
	Concurrency  int // max findings/batches processed in parallel (<=1 = sequential)
	FPThreshold  float64
	CostLimitUSD float64 // stop the run once cumulative AI cost exceeds this (0 = no limit)
	DryRun       bool
}

// Orchestrator wires the collaborators together.
type Orchestrator struct {
	cx   CheckmarxClient
	rev  ai.Reviewer
	src  *source.Reader
	opts Options
	log  *slog.Logger

	mu    sync.Mutex // guards spent (AI calls may run concurrently)
	spent ai.Usage   // cumulative token/cost usage across all AI calls this run
}

// New creates an Orchestrator. logger may be nil (logging is discarded).
func New(cx CheckmarxClient, rev ai.Reviewer, src *source.Reader, opts Options, logger *slog.Logger) *Orchestrator {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Orchestrator{cx: cx, rev: rev, src: src, opts: opts, log: logger}
}

// recordUsage accumulates one AI call's usage into the run total and logs it.
// Safe for concurrent callers.
func (o *Orchestrator) recordUsage(u ai.Usage) {
	if u == (ai.Usage{}) {
		return // agent reported no usage (e.g. Copilot, or a failed call)
	}
	o.mu.Lock()
	o.spent.Add(u)
	total := o.spent
	o.mu.Unlock()
	o.log.Info("ai call cost",
		"deltaUsd", fmt.Sprintf("%.4f", u.CostUSD),
		"in", u.InputTokens, "out", u.OutputTokens,
		"cache", u.CacheCreationInputTokens+u.CacheReadInputTokens,
		"runTotalUsd", fmt.Sprintf("%.4f", total.CostUSD),
		"runTotalTokens", total.TotalTokens())
}

// overBudget reports whether the cumulative cost has reached the configured
// limit. A limit of 0 (or less) disables the check. Safe for concurrent callers.
func (o *Orchestrator) overBudget() bool {
	if o.opts.CostLimitUSD <= 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.spent.CostUSD >= o.opts.CostLimitUSD
}

// runConcurrent runs work(0..count-1) with at most n invocations in flight. When
// n <= 1 it runs inline in index order, keeping behavior deterministic and
// avoiding goroutine overhead.
func runConcurrent(n, count int, work func(i int)) {
	if n <= 1 {
		for i := range count {
			work(i)
		}
		return
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := range count {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			work(i)
		}(i)
	}
	wg.Wait()
}

// Run executes the pipeline and returns the report. It returns an error only for
// fatal setup failures (auth, scan lookup, results listing, or a results response
// that is empty or missing vulnerability names); per-finding failures are
// recorded in the report and do not abort the run.
func (o *Orchestrator) Run(ctx context.Context) (*report.Report, error) {
	scan, err := o.cx.GetScan(ctx, o.opts.ScanID)
	if err != nil {
		return nil, fmt.Errorf("fetching scan: %w", err)
	}

	results, err := o.cx.ListToVerify(ctx, o.opts.ScanID, o.opts.Severities)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no %s/TO_VERIFY findings returned for scan %s",
			strings.Join(o.opts.Severities, "|"), o.opts.ScanID)
	}
	// The AI review is meaningless without the vulnerability name, so a response
	// omitting queryName is treated as a broken API response rather than reviewed.
	var missing []string
	for _, r := range results {
		if r.QueryName == "" {
			missing = append(missing, r.ID)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("sast results missing vulnerability names (queryName): %d of %d findings (e.g. result %s)",
			len(missing), len(results), missing[0])
	}

	// Deduplicate by similarityID: Checkmarx keys triage (history, predicates) at
	// the similarityID level, so result rows sharing one are the same finding
	// reached by different paths. Review the first occurrence once and record how
	// many rows it stands for.
	unique, dupes := dedupeBySimilarityID(results)

	rep := &report.Report{
		ScanID:         o.opts.ScanID,
		ProjectID:      scan.ProjectID,
		Severities:     o.opts.Severities,
		Agent:          o.opts.Agent,
		Model:          o.opts.Model,
		BatchSize:      o.opts.BatchSize,
		Concurrency:    max(o.opts.Concurrency, 1),
		FPThreshold:    o.opts.FPThreshold,
		DryRun:         o.opts.DryRun,
		GeneratedAt:    time.Now().UTC(),
		TotalFindings:  len(results),
		UniqueFindings: len(unique),
	}

	n := max(o.opts.Concurrency, 1)
	o.log.Info("reviewing findings", "count", len(results), "unique", len(unique),
		"scanId", o.opts.ScanID, "projectId", scan.ProjectID,
		"batchSize", o.opts.BatchSize, "concurrency", n)

	// Phase 1: prepare each finding (idempotency check + source evidence). Each
	// task writes a distinct index, so no locking is needed; the Checkmarx client
	// is concurrency-safe.
	items := make([]*item, len(unique))
	runConcurrent(n, len(unique), func(i int) {
		items[i] = o.prepare(ctx, scan.ProjectID, unique[i])
		items[i].fr.Duplicates = dupes[unique[i].SimilarityID]
	})

	// Phase 2: review non-terminal findings in bounded batches, with per-finding
	// fallback for anything a batch fails to answer. Stops early on cost limit.
	aborted := o.reviewBatches(ctx, items, n)

	// Phase 3: post verdicts (concurrently — each touches only its own item), then
	// assemble the report sequentially in original order so counters/order are
	// deterministic.
	runConcurrent(n, len(items), func(i int) {
		it := items[i]
		if !it.terminal && it.hasVerdict {
			o.applyVerdict(ctx, it)
		}
	})
	for _, it := range items {
		tally(rep, it.fr)
		rep.Findings = append(rep.Findings, it.fr)
	}

	// Record token/cost totals and any abort (cost limit or cancellation) on the
	// report.
	spent := o.snapshotSpent()
	rep.CostLimitUSD = o.opts.CostLimitUSD
	rep.EstimatedCostUSD = spent.CostUSD
	rep.InputTokens = spent.InputTokens
	rep.OutputTokens = spent.OutputTokens
	rep.TotalTokens = spent.TotalTokens()
	switch {
	case ctx.Err() != nil:
		rep.Aborted = true
		rep.AbortReason = "run cancelled before completion"
	case aborted:
		rep.Aborted = true
		rep.AbortReason = fmt.Sprintf("cost limit $%.2f reached (spent $%.4f)", o.opts.CostLimitUSD, spent.CostUSD)
	}

	o.log.Info("review complete", "reviewed", rep.Reviewed, "skipped", rep.Skipped,
		"errors", rep.Errors, "truePositives", rep.TruePositives,
		"falsePositives", rep.FalsePositives, "stateChanges", rep.StateChanges,
		"costUsd", fmt.Sprintf("%.4f", rep.EstimatedCostUSD), "tokens", rep.TotalTokens)

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
	simID := res.SimilarityID.String()
	it.fr = report.FindingResult{
		SimilarityID: simID,
		ResultHash:   res.ResultHash,
		QueryName:    res.QueryName,
		Severity:     res.Severity,
		NodesTotal:   len(res.Nodes),
	}
	if sink := sinkNode(res); sink != nil {
		it.fr.SinkFile = sink.FileName
		it.fr.SinkLine = sink.Line
	}

	// A cancelled run should not burn an API call per remaining finding.
	if ctx.Err() != nil {
		it.fr.Action = report.ActionSkippedCancelled
		it.terminal = true
		return it
	}

	history, err := o.cx.GetPredicateHistory(ctx, simID, projectID)
	if err != nil {
		o.log.Error("predicate history fetch failed", "similarityId", simID,
			"query", res.QueryName, "err", err)
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
	o.log.Debug("finding prepared", "similarityId", simID, "query", res.QueryName,
		"nodesTotal", len(res.Nodes), "nodesResolved", resolved)
	return it
}

// reviewBatches chunks the non-terminal items and reviews each batch with up to n
// batches in flight. Findings are stable-sorted so each chunk is homogeneous
// (same query/file), which keeps larger batches accurate and cache-friendly. It
// stops dispatching once the cost limit is exceeded, marking any not-yet-reviewed
// findings as budget-skipped, and reports whether it aborted for that reason.
//
// When n > 1 the cost-limit boundary is approximate: batches already in flight
// finish, so spend may overshoot the limit by up to n-1 batches. At n == 1 the
// stop is exact.
func (o *Orchestrator) reviewBatches(ctx context.Context, items []*item, n int) bool {
	var pending []*item
	for _, it := range items {
		if !it.terminal {
			pending = append(pending, it)
		}
	}
	if len(pending) == 0 {
		return false
	}

	// Group homogeneous findings together (same query, then sink location) so each
	// batch is cache-friendly; stable so equal keys keep their original order.
	sort.SliceStable(pending, func(a, b int) bool {
		x, y := pending[a], pending[b]
		if x.finding.QueryName != y.finding.QueryName {
			return x.finding.QueryName < y.finding.QueryName
		}
		if x.fr.SinkFile != y.fr.SinkFile {
			return x.fr.SinkFile < y.fr.SinkFile
		}
		return x.fr.SinkLine < y.fr.SinkLine
	})

	size := max(o.opts.BatchSize, 1)

	// Build the list of chunks up front so we can gate dispatch on the budget.
	type chunk struct{ start, end int }
	var chunks []chunk
	for start := 0; start < len(pending); start += size {
		chunks = append(chunks, chunk{start, min(start+size, len(pending))})
	}

	sem := make(chan struct{}, max(n, 1))
	var wg sync.WaitGroup
	aborted := false
	dispatched := 0
	for i, ch := range chunks {
		// Acquire a slot first: this blocks until fewer than n batches are in
		// flight, so the batches ahead of us have finished and recorded their usage
		// by the time we check the budget. At n==1 that makes the stop exact; at
		// n>1 overshoot is bounded to the batches still running.
		sem <- struct{}{}
		if ctx.Err() != nil {
			<-sem // release the unused slot
			o.log.Warn("run cancelled; stopping review", "unreviewedBatches", len(chunks)-i)
			markSkipped(pending[ch.start:], report.ActionSkippedCancelled)
			wg.Wait()
			return false // cancellation abort is recorded by Run via ctx
		}
		if o.overBudget() {
			<-sem // release the unused slot
			o.log.Warn("cost limit reached; stopping",
				"spentUsd", fmt.Sprintf("%.4f", o.snapshotSpent().CostUSD),
				"limitUsd", fmt.Sprintf("%.2f", o.opts.CostLimitUSD),
				"unreviewedBatches", len(chunks)-i)
			aborted = true
			break
		}
		wg.Add(1)
		dispatched++
		go func(batchNum, start, end int) {
			defer wg.Done()
			defer func() { <-sem }()
			o.log.Info("reviewing batch", "batch", batchNum, "size", end-start,
				"query", pending[start].finding.QueryName)
			o.reviewBatch(ctx, pending[start:end])
		}(i+1, ch.start, ch.end)
	}
	wg.Wait()

	if aborted {
		// Mark every finding in the chunks we never dispatched as budget-skipped.
		markSkipped(pending[chunks[dispatched].start:], report.ActionSkippedBudget)
		return true
	}
	// The individual-fallback path inside a dispatched batch may itself have hit
	// the cost limit (see reviewBatch); surface that as an abort too.
	for _, it := range pending {
		if it.fr.Action == report.ActionSkippedBudget {
			return true
		}
	}
	return false
}

// snapshotSpent returns a copy of the current usage totals under lock.
func (o *Orchestrator) snapshotSpent() ai.Usage {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.spent
}

// markSkipped records findings left unreviewed (cost limit hit or run cancelled)
// so they appear in the report rather than silently disappearing.
func markSkipped(items []*item, action string) {
	for _, it := range items {
		if it.terminal || it.hasVerdict {
			continue
		}
		it.fr.Action = action
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
		o.log.Warn("batch review failed; falling back to individual review",
			"size", len(batch), "err", err)
		o.reviewRemaining(ctx, batch)
		return
	}

	for id, v := range verdicts {
		if it, ok := byID[id]; ok {
			it.verdict = v
			it.hasVerdict = true
		}
	}
	o.reviewRemaining(ctx, batch)
}

// reviewRemaining retries each unanswered finding of a batch individually,
// respecting cancellation and the cost limit between calls so a failed batch
// cannot blow through the budget one finding at a time.
func (o *Orchestrator) reviewRemaining(ctx context.Context, batch []*item) {
	for i, it := range batch {
		if it.terminal || it.hasVerdict {
			continue
		}
		if ctx.Err() != nil {
			markSkipped(batch[i:], report.ActionSkippedCancelled)
			return
		}
		if o.overBudget() {
			o.log.Warn("cost limit reached during individual fallback; skipping rest",
				"remaining", len(batch)-i)
			markSkipped(batch[i:], report.ActionSkippedBudget)
			return
		}
		o.reviewIndividually(ctx, it)
	}
}

// reviewIndividually re-reviews a single finding (batch of one). On failure the
// finding is marked terminal with an ERROR outcome.
func (o *Orchestrator) reviewIndividually(ctx context.Context, it *item) {
	verdicts, usage, err := o.rev.Review(ctx, []ai.Finding{it.finding})
	o.recordUsage(usage)
	if err != nil {
		o.log.Error("ai review failed", "similarityId", it.finding.ID,
			"query", it.fr.QueryName, "err", err)
		it.fr.Action = report.ActionError
		it.fr.Error = fmt.Sprintf("ai review: %v", err)
		it.terminal = true
		return
	}
	v, ok := verdicts[it.finding.ID]
	if !ok {
		o.log.Warn("no verdict returned", "similarityId", it.finding.ID, "query", it.fr.QueryName)
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
	// On cancellation, record the verdict in the report but don't post it.
	if ctx.Err() != nil {
		it.fr.Verdict = it.verdict.Verdict
		it.fr.Confidence = it.verdict.Confidence
		it.fr.Explanation = it.verdict.Explanation
		it.fr.Action = report.ActionSkippedCancelled
		return
	}

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

	comment := formatComment(v)

	if o.opts.DryRun {
		return
	}

	if err := o.cx.PostPredicate(ctx, it.res.SimilarityID.String(), it.projectID, it.res.Severity, state, comment); err != nil {
		o.log.Error("posting predicate failed", "similarityId", it.res.SimilarityID.String(),
			"query", it.fr.QueryName, "state", state, "err", err)
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
		ID:        res.SimilarityID.String(),
		QueryName: res.QueryName,
		Group:     res.Group,
		Language:  res.LanguageName,
		Severity:  res.Severity,
	}
	if f.QueryName == "" || len(res.Nodes) == 0 {
		o.log.Warn("finding has incomplete evidence for AI review",
			"similarityId", f.ID, "queryName", f.QueryName, "nodes", len(res.Nodes))
	}
	resolved := 0
	for i, n := range res.Nodes {
		snip := o.src.SnippetFor(n.FileName, n.Line)
		nc := ai.NodeContext{
			Order:    i + 1,
			FileName: n.FileName,
			Line:     n.Line,
			Name:     n.Name,
			Resolved: snip.Resolved,
		}
		if snip.Resolved {
			nc.Snippet = snip.Code
			nc.StartLine = snip.StartLine
			nc.EndLine = snip.EndLine
			resolved++
		} else {
			nc.Snippet = snip.Note
			o.log.Debug("source unresolved", "similarityId", res.SimilarityID.String(),
				"file", n.FileName, "line", n.Line, "note", snip.Note)
		}
		f.Nodes = append(f.Nodes, nc)
	}
	return f, resolved
}

// dedupeBySimilarityID keeps the first result for each similarityID (in input
// order) and counts the extra rows folded into it.
func dedupeBySimilarityID(results []checkmarx.Result) ([]checkmarx.Result, map[checkmarx.SimilarityID]int) {
	var unique []checkmarx.Result
	dupes := make(map[checkmarx.SimilarityID]int)
	seen := make(map[checkmarx.SimilarityID]bool, len(results))
	for _, res := range results {
		if seen[res.SimilarityID] {
			dupes[res.SimilarityID]++
			continue
		}
		seen[res.SimilarityID] = true
		unique = append(unique, res)
	}
	return unique, dupes
}

// sinkNode returns the last node of the data-flow path (the sink), or nil.
func sinkNode(res checkmarx.Result) *checkmarx.Node {
	if len(res.Nodes) == 0 {
		return nil
	}
	return &res.Nodes[len(res.Nodes)-1]
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
func formatComment(v ai.Verdict) string {
	label := "TRUE POSITIVE"
	if v.IsFalsePositive() {
		label = "FALSE POSITIVE"
	}
	return fmt.Sprintf("%s %s — confidence %d%%\n%s\n—\nreviewed %s · checkmarx-reviewer",
		commentMarker,
		label,
		int(v.Confidence*100+0.5),
		strings.TrimSpace(v.Explanation),
		time.Now().UTC().Format("2006-01-02"),
	)
}

// tally updates report counters from a finding outcome.
func tally(rep *report.Report, fr report.FindingResult) {
	switch fr.Action {
	case report.ActionSkippedAlreadyDone, report.ActionSkippedBudget, report.ActionSkippedCancelled:
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
