package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMultiHandlerFansOutRespectingLevels(t *testing.T) {
	var info, debug bytes.Buffer
	infoH := slog.NewTextHandler(&info, &slog.HandlerOptions{Level: slog.LevelInfo})
	debugH := slog.NewJSONHandler(&debug, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(NewMultiHandler(infoH, debugH))

	logger.Debug("only for the file", "k", "v")
	logger.Info("for both")

	if strings.Contains(info.String(), "only for the file") {
		t.Errorf("info handler received a debug record:\n%s", info.String())
	}
	if !strings.Contains(info.String(), "for both") {
		t.Errorf("info handler missed an info record:\n%s", info.String())
	}
	for _, want := range []string{"only for the file", "for both"} {
		if !strings.Contains(debug.String(), want) {
			t.Errorf("debug handler missed %q:\n%s", want, debug.String())
		}
	}
}

func TestMultiHandlerWithAttrsAndGroup(t *testing.T) {
	var buf bytes.Buffer
	h := NewMultiHandler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(h).With("run", "r1").WithGroup("g")
	logger.Info("msg", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if rec["run"] != "r1" {
		t.Errorf("With attr lost: %v", rec)
	}
	g, ok := rec["g"].(map[string]any)
	if !ok || g["k"] != "v" {
		t.Errorf("WithGroup attr lost: %v", rec)
	}
}

func TestMultiHandlerEnabled(t *testing.T) {
	h := NewMultiHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)
	if !h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled(Debug) = false; want true when any child is enabled")
	}
}

func TestNewRunWritesDebugJSONLWithoutVerbose(t *testing.T) {
	base := t.TempDir()
	logger, run, err := NewRun(base, "scan-1234567890", false)
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	defer run.Close()

	logger.Debug("debug entry", "k", "v")
	logger.Info("info entry")

	data, err := os.ReadFile(filepath.Join(run.Dir(), runLogFile))
	if err != nil {
		t.Fatalf("reading run log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2:\n%s", len(lines), data)
	}
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("line is not JSON: %v\n%s", err, line)
		}
	}
	if !strings.Contains(lines[0], "debug entry") {
		t.Errorf("file log missed the debug record without --verbose:\n%s", lines[0])
	}
	if base := filepath.Base(run.Dir()); !strings.HasSuffix(base, "_scan-123") {
		t.Errorf("run dir %q does not end in the scan-id prefix", base)
	}
}

func TestNewRunDisabled(t *testing.T) {
	logger, run, err := NewRun("", "scan-1", false)
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	if run != nil {
		t.Fatalf("run should be nil when disabled, got %+v", run)
	}
	// All nil-receiver methods must no-op.
	if got := run.Dir(); got != "" {
		t.Errorf("nil run Dir() = %q, want empty", got)
	}
	if got := run.Dump("cat", "name", []byte("x")); got != "" {
		t.Errorf("nil run Dump() = %q, want empty", got)
	}
	if err := run.Close(); err != nil {
		t.Errorf("nil run Close() = %v, want nil", err)
	}
	logger.Info("must not panic")
}

func TestDumpConcurrentUniqueFiles(t *testing.T) {
	_, run, err := NewRun(t.TempDir(), "scan-1", false)
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	defer run.Close()

	const n = 20
	paths := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i] = run.Dump("checkmarx", "GET_api_sast-results.json", []byte("body"))
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for _, p := range paths {
		if p == "" {
			t.Fatal("Dump returned empty path")
		}
		if seen[p] {
			t.Fatalf("duplicate dump path %s", p)
		}
		seen[p] = true
		if _, err := os.Stat(p); err != nil {
			t.Errorf("dump file missing: %v", err)
		}
	}
}

func TestDumpSanitizesNames(t *testing.T) {
	_, run, err := NewRun(t.TempDir(), "scan-1", false)
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	defer run.Close()

	p := run.Dump("checkmarx", "../../etc/passwd", []byte("x"))
	if p == "" {
		t.Fatal("Dump returned empty path")
	}
	rel, err := filepath.Rel(run.Dir(), p)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("dump escaped the run dir: %s", p)
	}
}

func TestRedaction(t *testing.T) {
	base := t.TempDir()
	logger, run, err := NewRun(base, "scan-1", false)
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	logger.Info("auth", "token", "sekret-value", "authorization", "Bearer abc",
		"inputTokens", 42)
	run.Close()

	data, err := os.ReadFile(filepath.Join(run.Dir(), runLogFile))
	if err != nil {
		t.Fatalf("reading run log: %v", err)
	}
	if strings.Contains(string(data), "sekret-value") || strings.Contains(string(data), "Bearer abc") {
		t.Errorf("credential value reached the log file:\n%s", data)
	}
	if !strings.Contains(string(data), "[REDACTED]") {
		t.Errorf("expected redaction marker in log file:\n%s", data)
	}
	if !strings.Contains(string(data), "42") {
		t.Errorf("non-credential key inputTokens was wrongly redacted:\n%s", data)
	}
}
