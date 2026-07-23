package review

import (
	"log/slog"
	"sync"
)

// progress tracks completion of a set of concurrently processed tasks and logs
// throttled milestone lines (~every 10%) plus a final "complete" line, so a long
// phase (AI batches, comment posting) shows a running percentage instead of going
// silent. It is safe for concurrent callers. Per-task failures are logged where
// they occur; the failed=F counter here is a running tally on top of those.
type progress struct {
	log   *slog.Logger
	label string
	total int
	step  int // log every `step` completions (~10% of total)

	mu   sync.Mutex
	done int
	fail int
	next int // next milestone threshold
}

// newProgress starts tracking a phase of total tasks and logs a "starting" line.
// A total of 0 yields a tracker whose record is a no-op (empty phases stay quiet
// and division-by-zero is avoided).
func newProgress(log *slog.Logger, label string, total int) *progress {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	step := max(1, total/10)
	p := &progress{log: log, label: label, total: total, step: step, next: step}
	if total > 0 {
		log.Info(label+": starting", "total", total)
	}
	return p
}

// record marks one task done (failed=true also counts it as a failure) and logs a
// milestone line when completion crosses the next ~10% threshold or reaches total.
func (p *progress) record(failed bool) {
	if p.total == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	if failed {
		p.fail++
	}
	if p.done < p.next && p.done < p.total {
		return
	}
	msg := p.label + ": progress"
	if p.done >= p.total {
		msg = p.label + ": complete"
	}
	p.log.Info(msg, "done", p.done, "total", p.total,
		"pct", p.done*100/p.total, "failed", p.fail)
	for p.next <= p.done {
		p.next += p.step
	}
}
