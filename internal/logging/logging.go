// Package logging builds the per-run logger: human-readable text on stderr plus
// debug-level JSON lines and raw artifact dumps (API bodies, prompts, agent
// output) in a per-run directory, so any run can be diagnosed after the fact.
package logging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// runLogFile is the JSON-lines log file inside each run directory.
const runLogFile = "run.jsonl"

// NewRun builds the logger for one run. Stderr keeps the existing text handler
// (Info, or Debug when verbose). When baseDir is non-empty, a per-run directory
// <baseDir>/<UTC timestamp>_<scanID prefix> is created holding a run.jsonl
// JSON-lines log — always at Debug level, so full diagnostics are captured even
// without --verbose — and the returned *Run can dump raw artifacts alongside it.
// With an empty baseDir the logger is stderr-only and the returned *Run is nil
// (which is valid: all its methods no-op).
func NewRun(baseDir, scanID string, verbose bool) (*slog.Logger, *Run, error) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	stderrH := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	if baseDir == "" {
		return slog.New(stderrH), nil, nil
	}

	name := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	if prefix := sanitizeName(scanID); prefix != "" {
		name += "_" + prefix[:min(len(prefix), 8)]
	}
	dir := filepath.Join(baseDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating log directory %s: %w", dir, err)
	}
	f, err := os.OpenFile(filepath.Join(dir, runLogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("creating log file: %w", err)
	}

	fileH := slog.NewJSONHandler(f, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: redactAttr,
	})
	return slog.New(NewMultiHandler(stderrH, fileH)), &Run{dir: dir, file: f}, nil
}

// Run owns one run's log file and artifact dump directory. A nil *Run is valid:
// all methods no-op, so callers never need to check whether file logging is on.
type Run struct {
	dir  string
	file *os.File
	seq  atomic.Int64 // makes dump filenames unique under concurrency
}

// Dir returns the run's log directory, or "" when file logging is disabled.
func (r *Run) Dir() string {
	if r == nil {
		return ""
	}
	return r.dir
}

// Close closes the run's log file.
func (r *Run) Close() error {
	if r == nil {
		return nil
	}
	return r.file.Close()
}

// Dump writes a raw artifact to <runDir>/<category>/<seq>_<name> and returns
// the written path. Failures are reported on stderr and return "" — a dump is
// diagnostics, never worth failing the run for. Safe for concurrent use.
func (r *Run) Dump(category, name string, data []byte) string {
	if r == nil {
		return ""
	}
	dir := filepath.Join(r.dir, sanitizeName(category))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "logging: creating dump directory %s: %v\n", dir, err)
		return ""
	}
	path := filepath.Join(dir, fmt.Sprintf("%04d_%s", r.seq.Add(1), sanitizeName(name)))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "logging: writing dump %s: %v\n", path, err)
		return ""
	}
	return path
}

// sanitizeName reduces s to a safe filename component.
func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// redactedKeys are attribute keys (lowercased, exact match) whose values must
// never reach the log file. Nothing logs credentials today; this is a backstop.
var redactedKeys = map[string]bool{
	"authorization": true,
	"apikey":        true,
	"api_key":       true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"bearer":        true,
	"secret":        true,
	"password":      true,
}

// redactAttr blanks the value of credential-like attribute keys.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if redactedKeys[strings.ToLower(a.Key)] {
		a.Value = slog.StringValue("[REDACTED]")
	}
	return a
}

// NewMultiHandler returns a slog.Handler that forwards each record to every
// child handler enabled for the record's level.
func NewMultiHandler(handlers ...slog.Handler) slog.Handler {
	return &multiHandler{handlers: handlers}
}

type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: hs}
}
