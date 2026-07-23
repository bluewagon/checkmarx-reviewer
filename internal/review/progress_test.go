package review

import (
	"context"
	"log/slog"
	"sync"
	"testing"
)

// capture is a slog.Handler that records the message and selected attrs of every
// Info+ record, so tests can assert which milestone lines were emitted.
type capture struct {
	mu      sync.Mutex
	records []map[string]any
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }

func (c *capture) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{"msg": r.Message}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	c.mu.Lock()
	c.records = append(c.records, m)
	c.mu.Unlock()
	return nil
}

func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// progressLines returns only the milestone records (msg ends in ": progress" or
// ": complete"), skipping the ": starting" line.
func (c *capture) progressLines() []map[string]any {
	var out []map[string]any
	for _, r := range c.records {
		msg, _ := r["msg"].(string)
		if msg == "reviewing batches: progress" || msg == "reviewing batches: complete" {
			out = append(out, r)
		}
	}
	return out
}

func TestProgressMilestonesEveryTenPercent(t *testing.T) {
	cap := &capture{}
	log := slog.New(cap)
	p := newProgress(log, "reviewing batches", 10)
	for range 10 {
		p.record(false)
	}
	// total=10 → step=1 → a milestone line for each completion (1..10).
	lines := cap.progressLines()
	if len(lines) != 10 {
		t.Fatalf("want 10 milestone lines, got %d: %v", len(lines), lines)
	}
	last := lines[len(lines)-1]
	if last["msg"] != "reviewing batches: complete" {
		t.Errorf("final line msg = %v, want complete", last["msg"])
	}
	if got := last["pct"]; got != int64(100) {
		t.Errorf("final pct = %v, want 100", got)
	}
	if got := last["done"]; got != int64(10) {
		t.Errorf("final done = %v, want 10", got)
	}
}

func TestProgressLargeTotalThrottles(t *testing.T) {
	cap := &capture{}
	log := slog.New(cap)
	p := newProgress(log, "reviewing batches", 100) // step = 10
	for range 100 {
		p.record(false)
	}
	// Milestones at 10,20,...,100 → 10 lines.
	lines := cap.progressLines()
	if len(lines) != 10 {
		t.Fatalf("want 10 milestone lines for total=100, got %d", len(lines))
	}
	if got := lines[0]["done"]; got != int64(10) {
		t.Errorf("first milestone done = %v, want 10", got)
	}
	if got := lines[len(lines)-1]["msg"]; got != "reviewing batches: complete" {
		t.Errorf("last milestone msg = %v, want complete", got)
	}
}

func TestProgressSmallTotalStepIsOne(t *testing.T) {
	cap := &capture{}
	log := slog.New(cap)
	p := newProgress(log, "reviewing batches", 3) // step = max(1, 3/10) = 1
	for range 3 {
		p.record(false)
	}
	if got := len(cap.progressLines()); got != 3 {
		t.Fatalf("want 3 milestone lines for total=3, got %d", got)
	}
}

func TestProgressFailedTally(t *testing.T) {
	cap := &capture{}
	log := slog.New(cap)
	p := newProgress(log, "reviewing batches", 4) // step = 1
	p.record(true)
	p.record(false)
	p.record(true)
	p.record(false)
	lines := cap.progressLines()
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d", len(lines))
	}
	if got := lines[len(lines)-1]["failed"]; got != int64(2) {
		t.Errorf("final failed = %v, want 2", got)
	}
}

func TestProgressZeroTotalIsNoOp(t *testing.T) {
	cap := &capture{}
	log := slog.New(cap)
	p := newProgress(log, "reviewing batches", 0)
	p.record(false)
	p.record(true)
	if len(cap.records) != 0 {
		t.Fatalf("total=0 should emit no lines, got %d: %v", len(cap.records), cap.records)
	}
}
