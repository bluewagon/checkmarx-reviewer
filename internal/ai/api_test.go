package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/option"
)

// newAPIReviewerForTest points the SDK client at a fake Messages endpoint.
func newAPIReviewerForTest(t *testing.T, handler http.HandlerFunc, agentic bool, workDir string) *APIReviewer {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	r, err := NewAPIReviewer("", time.Minute, agentic, workDir, nil, nil,
		option.WithBaseURL(srv.URL), option.WithAPIKey("test-key"), option.WithMaxRetries(0))
	if err != nil {
		t.Fatalf("NewAPIReviewer: %v", err)
	}
	return r
}

// messageEnvelope renders a minimal Messages API response.
func messageEnvelope(content string, stop string, blocks ...map[string]any) map[string]any {
	if blocks == nil {
		blocks = []map[string]any{{"type": "text", "text": content}}
	}
	return map[string]any{
		"id": "msg_test", "type": "message", "role": "assistant",
		"model":       "claude-opus-4-8",
		"content":     blocks,
		"stop_reason": stop,
		"usage": map[string]any{
			"input_tokens": 1000, "output_tokens": 100,
			"cache_creation_input_tokens": 200, "cache_read_input_tokens": 400,
		},
	}
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestAPIReviewMapsVerdictsAndComputesCost(t *testing.T) {
	var gotBody string
	handler := func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		gotBody = string(b)
		writeJSONResp(w, messageEnvelope(
			`[{"id":"sim-1","verdict":"FALSE_POSITIVE","confidence":0.95,"explanation":"validated"}]`,
			"end_turn"))
	}
	r := newAPIReviewerForTest(t, handler, false, "")

	got, usage, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(got) != 1 || !got["sim-1"].IsFalsePositive() {
		t.Errorf("verdicts = %+v", got)
	}
	if !strings.Contains(gotBody, "id=sim-1") {
		t.Error("request should carry the batch prompt")
	}
	if !strings.Contains(gotBody, `"adaptive"`) {
		t.Error("request should enable adaptive thinking")
	}
	if usage.InputTokens != 1000 || usage.OutputTokens != 100 ||
		usage.CacheCreationInputTokens != 200 || usage.CacheReadInputTokens != 400 {
		t.Errorf("usage tokens not mapped: %+v", usage)
	}
	// opus-4-8: (1000*5 + 100*25 + 200*5*1.25 + 400*5*0.1)/1e6
	want := (1000*5.0 + 100*25.0 + 200*5.0*1.25 + 400*5.0*0.1) / 1e6
	if diff := usage.CostUSD - want; diff > 1e-12 || diff < -1e-12 {
		t.Errorf("cost = %v, want %v", usage.CostUSD, want)
	}
}

func TestAPIAgenticToolRoundTrip(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "a.jsp"), []byte("<%= request.getParameter(\"q\") %>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	calls := 0
	var secondBody string
	handler := func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		calls++
		switch calls {
		case 1:
			// Model asks to Read the file.
			writeJSONResp(w, messageEnvelope("", "tool_use", map[string]any{
				"type": "tool_use", "id": "toolu_1", "name": "Read",
				"input": map[string]any{"path": "a.jsp"},
			}))
		default:
			secondBody = string(b)
			writeJSONResp(w, messageEnvelope(
				`[{"id":"sim-1","verdict":"TRUE_POSITIVE","confidence":0.9,"explanation":"unescaped param reaches JSP output","agentic_source":true}]`,
				"end_turn"))
		}
	}
	r := newAPIReviewerForTest(t, handler, true, repo)

	got, usage, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 API calls (tool round-trip), got %d", calls)
	}
	if !strings.Contains(secondBody, "toolu_1") || !strings.Contains(secondBody, "tool_result") {
		t.Errorf("second request missing tool_result for toolu_1")
	}
	if !strings.Contains(secondBody, "request.getParameter") {
		t.Errorf("tool_result should carry the file contents, body: %s", truncate(secondBody, 300))
	}
	if got["sim-1"].Verdict != VerdictTruePositive {
		t.Errorf("verdict = %+v", got)
	}
	// Tools were used, so the self-reported agentic_source flag stands.
	if !got["sim-1"].AgenticSource {
		t.Errorf("agentic_source should be preserved when tools were used: %+v", got["sim-1"])
	}
	// Usage accumulates across both loop iterations.
	if usage.InputTokens != 2000 || usage.OutputTokens != 200 {
		t.Errorf("usage should sum across iterations: %+v", usage)
	}
}

func TestAPIAgenticNoToolUseClearsAgenticSource(t *testing.T) {
	// The model answers immediately without invoking any repo tool but still
	// self-reports agentic_source; the mechanical cross-check must clear it.
	handler := func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, messageEnvelope(
			`[{"id":"sim-1","verdict":"FALSE_POSITIVE","confidence":0.95,"explanation":"validated","agentic_source":true}]`,
			"end_turn"))
	}
	r := newAPIReviewerForTest(t, handler, true, t.TempDir())

	got, _, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if got["sim-1"].AgenticSource {
		t.Errorf("agentic_source should be cleared when no tool was invoked: %+v", got["sim-1"])
	}
}

func TestAPIAgenticToolsAreSandboxed(t *testing.T) {
	repo := t.TempDir()
	calls := 0
	var secondBody string
	handler := func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		calls++
		if calls == 1 {
			writeJSONResp(w, messageEnvelope("", "tool_use", map[string]any{
				"type": "tool_use", "id": "toolu_esc", "name": "Read",
				"input": map[string]any{"path": "../../etc/passwd"},
			}))
			return
		}
		secondBody = string(b)
		writeJSONResp(w, messageEnvelope(
			`[{"id":"sim-1","verdict":"TRUE_POSITIVE","confidence":0.5,"explanation":"x"}]`,
			"end_turn"))
	}
	r := newAPIReviewerForTest(t, handler, true, repo)

	if _, _, err := r.Review(context.Background(), findings("sim-1")); err != nil {
		t.Fatalf("Review should recover from a rejected tool call: %v", err)
	}
	if !strings.Contains(secondBody, "outside the repository root") {
		t.Errorf("traversal should be rejected as a tool error, body: %s", truncate(secondBody, 300))
	}
	if strings.Contains(secondBody, "root:") {
		t.Error("tool result must not contain /etc/passwd contents")
	}
}

func TestAPIReviewSurfacesAPIError(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	}
	r := newAPIReviewerForTest(t, handler, false, "")

	_, _, err := r.Review(context.Background(), findings("sim-1"))
	if err == nil || !strings.Contains(err.Error(), "anthropic api call failed") {
		t.Fatalf("expected wrapped api error, got %v", err)
	}
}

func TestComputeCost(t *testing.T) {
	cases := []struct {
		model string
		want  float64
	}{
		{"claude-opus-4-8", (1e6*5 + 1e6*25) / 1e6},
		{"claude-haiku-4-5-20251001", (1e6*1 + 1e6*5) / 1e6}, // prefix match on dated id
		{"claude-fable-5", (1e6*10 + 1e6*50) / 1e6},
		{"some-unknown-model", 0},
	}
	for _, c := range cases {
		if got := computeCost(c.model, 1e6, 1e6, 0, 0); got != c.want {
			t.Errorf("computeCost(%s) = %v, want %v", c.model, got, c.want)
		}
	}
}

func TestRepoToolHelpers(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src", "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src", "web", "page.jsp"), []byte("out.print(q);\nsafe();\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := toolRead(repo, readInput{Path: "src/web/page.jsp"}); !strings.Contains(got, "1| out.print(q);") {
		t.Errorf("Read output wrong:\n%s", got)
	}
	if got := toolGrep(repo, grepInput{Pattern: `out\.print`}); !strings.Contains(got, "src/web/page.jsp:1:") {
		t.Errorf("Grep output wrong:\n%s", got)
	}
	if got := toolGlob(repo, globInput{Pattern: "**/*.jsp"}); !strings.Contains(got, "src/web/page.jsp") {
		t.Errorf("Glob output wrong:\n%s", got)
	}
	if got := toolLS(repo, lsInput{Path: "src"}); !strings.Contains(got, "web/") {
		t.Errorf("LS output wrong:\n%s", got)
	}
	if got := toolGrep(repo, grepInput{Pattern: "nomatch-xyz"}); got != "no matches" {
		t.Errorf("Grep no-match = %q", got)
	}
}

func TestNewReviewerDispatch(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test")
	rev, err := NewReviewer(AgentAnthropic, "", "", time.Minute, false, "", nil, nil)
	if err != nil {
		t.Fatalf("NewReviewer(anthropic): %v", err)
	}
	if _, ok := rev.(*APIReviewer); !ok {
		t.Errorf("anthropic should build an APIReviewer, got %T", rev)
	}
	if rev.Model() != apiDefaultModel {
		t.Errorf("default model = %q, want %q", rev.Model(), apiDefaultModel)
	}
	if _, err := NewReviewer("gemini", "", "", 0, false, "", nil, nil); err == nil {
		t.Error("unknown agent should error")
	}
}
