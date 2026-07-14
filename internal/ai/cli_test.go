package ai

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestExtractVerdictsPureArray(t *testing.T) {
	vs, err := extractVerdicts(`[{"id":"a","verdict":"TRUE_POSITIVE","confidence":0.8,"explanation":"x"},{"id":"b","verdict":"FALSE_POSITIVE","confidence":0.5,"explanation":"y"}]`)
	if err != nil {
		t.Fatalf("extractVerdicts: %v", err)
	}
	if len(vs) != 2 || vs[0].ID != "a" || vs[1].Verdict != VerdictFalsePositive {
		t.Errorf("got %+v", vs)
	}
}

func TestExtractVerdictsArrayInProseAndFences(t *testing.T) {
	text := "Here you go:\n```json\n[{\"id\": \"sim-1\", \"verdict\": \"FALSE_POSITIVE\", \"confidence\": 0.91, \"explanation\": \"validated { and } inside\"}]\n```\nDone."
	vs, err := extractVerdicts(text)
	if err != nil {
		t.Fatalf("extractVerdicts: %v", err)
	}
	if len(vs) != 1 || !vs[0].IsFalsePositive() || vs[0].ID != "sim-1" {
		t.Errorf("got %+v", vs)
	}
}

func TestExtractVerdictsFallbackToObjects(t *testing.T) {
	// No array wrapper; loose objects, one without a verdict must be ignored.
	text := `{"note":"ignore"} {"id":"a","verdict":"TRUE_POSITIVE","confidence":1,"explanation":"reaches sink"}`
	vs, err := extractVerdicts(text)
	if err != nil {
		t.Fatalf("extractVerdicts: %v", err)
	}
	if len(vs) != 1 || vs[0].ID != "a" {
		t.Errorf("got %+v", vs)
	}
}

func TestExtractVerdictsNone(t *testing.T) {
	if _, err := extractVerdicts("I cannot help with that."); err == nil {
		t.Fatal("expected error when no verdict present")
	}
}

func TestExtractClaudeResultUnwrapsEnvelope(t *testing.T) {
	env := `{"type":"result","is_error":false,"total_cost_usd":0.0123,"usage":{"input_tokens":1500,"output_tokens":200,"cache_read_input_tokens":50},"result":"[{\"id\":\"a\",\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.9,\"explanation\":\"safe\"}]"}`
	got, usage, isErr := extractClaudeResult([]byte(env))
	if !strings.Contains(got, "FALSE_POSITIVE") {
		t.Fatalf("did not unwrap result: %q", got)
	}
	if isErr {
		t.Error("is_error=false envelope should not flag an error")
	}
	if usage.CostUSD != 0.0123 || usage.InputTokens != 1500 || usage.OutputTokens != 200 || usage.CacheReadInputTokens != 50 {
		t.Errorf("usage not parsed from envelope: %+v", usage)
	}
	if usage.TotalTokens() != 1750 {
		t.Errorf("total tokens = %d, want 1750", usage.TotalTokens())
	}
	raw := `[{"id":"a","verdict":"TRUE_POSITIVE"}]`
	if got, usage, isErr := extractClaudeResult([]byte(raw)); got != raw || usage != (Usage{}) || isErr {
		t.Error("raw JSON should pass through unchanged with zero usage")
	}
}

func TestClaudeIsErrorEnvelopeSurfacesAgentError(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","is_error":true,"result":"Credit balance too low"}`}
	r := newReviewerForTest(AgentClaude, cr.run)

	_, _, err := r.Review(context.Background(), findings("sim-1"))
	if err == nil {
		t.Fatal("expected error for is_error envelope")
	}
	if !strings.Contains(err.Error(), "Credit balance too low") {
		t.Errorf("error should carry the agent's message, got: %v", err)
	}
	if strings.Contains(err.Error(), "no JSON verdict") {
		t.Errorf("agent error must not be misreported as a parse failure: %v", err)
	}
}

// captureRunner records how the CLI was invoked and returns a canned response.
type captureRunner struct {
	bin    string
	args   []string
	stdin  string
	dir    string
	stdout string
	stderr string
	err    error
}

func (c *captureRunner) run(_ context.Context, bin string, args []string, stdin []byte, dir string) ([]byte, []byte, error) {
	c.bin, c.args, c.stdin, c.dir = bin, args, string(stdin), dir
	return []byte(c.stdout), []byte(c.stderr), c.err
}

func newReviewerForTest(agent string, run runner) *CLIReviewer {
	spec := agentSpecs[agent]
	return &CLIReviewer{agent: agent, spec: spec, bin: spec.bin, model: spec.defaultModel, timeout: time.Second, log: slog.New(slog.DiscardHandler), run: run}
}

// newAgenticReviewerForTest builds a reviewer with agentic mode and a work dir.
func newAgenticReviewerForTest(agent, workDir string, run runner) *CLIReviewer {
	r := newReviewerForTest(agent, run)
	r.agentic = true
	r.workDir = workDir
	return r
}

func findings(ids ...string) []Finding {
	fs := make([]Finding, len(ids))
	for i, id := range ids {
		fs[i] = Finding{ID: id, QueryName: "SQL_Injection", Nodes: []NodeContext{{Order: 1, FileName: "a.go", Line: 1, Snippet: "1| x", Resolved: true, StartLine: 1, EndLine: 1}}}
	}
	return fs
}

func TestClaudeBatchReviewMapsByID(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","is_error":false,"total_cost_usd":0.02,"usage":{"input_tokens":800,"output_tokens":120},"result":"[{\"id\":\"sim-1\",\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.95,\"explanation\":\"validated\"},{\"id\":\"sim-2\",\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.7,\"explanation\":\"reaches sink\"}]"}`}
	r := newReviewerForTest(AgentClaude, cr.run)

	got, usage, err := r.Review(context.Background(), findings("sim-1", "sim-2"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(got) != 2 || !got["sim-1"].IsFalsePositive() || got["sim-2"].Verdict != VerdictTruePositive {
		t.Errorf("verdicts = %+v", got)
	}
	if usage.CostUSD != 0.02 || usage.TotalTokens() != 920 {
		t.Errorf("usage not surfaced from Review: %+v", usage)
	}
	if !strings.Contains(cr.stdin, "id=sim-1") || !strings.Contains(cr.stdin, "id=sim-2") {
		t.Error("prompt (stdin) should contain both finding ids")
	}
	if !slices.Contains(cr.args, "--output-format") {
		t.Errorf("claude args missing flags: %v", cr.args)
	}
	// Non-agentic runs inherit the cwd and grant no repo tools.
	if cr.dir != "" {
		t.Errorf("non-agentic run should not set a working dir, got %q", cr.dir)
	}
	if slices.Contains(cr.args, "--allowedTools") {
		t.Errorf("non-agentic run should not grant tools: %v", cr.args)
	}
}

func TestAgenticClaudeSetsWorkDirAndTools(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","result":"[{\"id\":\"sim-1\",\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.8,\"explanation\":\"x\"}]"}`}
	r := newAgenticReviewerForTest(AgentClaude, "/repo/root", cr.run)

	if _, _, err := r.Review(context.Background(), findings("sim-1")); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if cr.dir != "/repo/root" {
		t.Errorf("agentic run should set working dir to repo root, got %q", cr.dir)
	}
	i := slices.Index(cr.args, "--allowedTools")
	if i < 0 || i+1 >= len(cr.args) {
		t.Fatalf("agentic claude args missing --allowedTools: %v", cr.args)
	}
	if tools := cr.args[i+1]; !strings.Contains(tools, "Read") || !strings.Contains(tools, "Grep") {
		t.Errorf("read-only tools not granted: %q", tools)
	}
	// The agentic prompt must invite the agent to read/search the repo.
	if !strings.Contains(cr.stdin, "working directory") || !strings.Contains(cr.stdin, "read-only tools") {
		t.Errorf("agentic prompt missing repo-access guidance: %q", cr.stdin)
	}
}

func TestCopilotReviewSendsPromptAsArg(t *testing.T) {
	cr := &captureRunner{stdout: "Thinking...\n[{\"id\":\"sim-1\",\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.7,\"explanation\":\"reaches sink\"}]\n"}
	r := newReviewerForTest(AgentCopilot, cr.run)

	got, _, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if got["sim-1"].Verdict != VerdictTruePositive {
		t.Errorf("verdict = %+v", got)
	}
	if cr.stdin != "" {
		t.Error("copilot should not use stdin")
	}
	if len(cr.args) == 0 || !strings.Contains(cr.args[len(cr.args)-1], "id=sim-1") {
		t.Errorf("copilot should receive prompt as final arg: %v", cr.args)
	}
	// Non-agentic Copilot must not enable tools; it should deny them so it reasons
	// only from the inlined snippets instead of attempting (and failing) searches.
	if slices.Contains(cr.args, "--allow-all-tools") {
		t.Errorf("non-agentic copilot should not enable tools: %v", cr.args)
	}
	if !slices.Contains(cr.args, "--deny-tool") {
		t.Errorf("non-agentic copilot should deny tools: %v", cr.args)
	}
	// -p must remain immediately before the prompt (the final arg).
	if pi := slices.Index(cr.args, "-p"); pi != len(cr.args)-2 {
		t.Errorf("-p should immediately precede the prompt arg: %v", cr.args)
	}
}

func TestAgenticCopilotAllowsTools(t *testing.T) {
	cr := &captureRunner{stdout: "[{\"id\":\"sim-1\",\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.7,\"explanation\":\"reaches sink\"}]\n"}
	r := newAgenticReviewerForTest(AgentCopilot, "/repo/root", cr.run)

	if _, _, err := r.Review(context.Background(), findings("sim-1")); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if cr.dir != "/repo/root" {
		t.Errorf("agentic copilot should run in the repo root, got %q", cr.dir)
	}
	if !slices.Contains(cr.args, "--allow-all-tools") || !slices.Contains(cr.args, "--allow-all-paths") {
		t.Errorf("agentic copilot should grant tools and path trust: %v", cr.args)
	}
	if slices.Contains(cr.args, "--deny-tool") {
		t.Errorf("agentic copilot should not deny tools: %v", cr.args)
	}
}

func TestSingleItemIDBackfill(t *testing.T) {
	// Agent omitted the id on a single-item batch; it should be backfilled.
	cr := &captureRunner{stdout: `{"type":"result","result":"[{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.9,\"explanation\":\"safe\"}]"}`}
	r := newReviewerForTest(AgentClaude, cr.run)

	got, _, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if _, ok := got["sim-1"]; !ok {
		t.Errorf("expected id backfilled to sim-1, got %+v", got)
	}
}

func TestInvalidVerdictDroppedFromMap(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","result":"[{\"id\":\"sim-1\",\"verdict\":\"MAYBE\",\"confidence\":0.5,\"explanation\":\"x\"}]"}`}
	r := newReviewerForTest(AgentClaude, cr.run)

	got, _, err := r.Review(context.Background(), findings("sim-1"))
	if err != nil {
		t.Fatalf("Review should not hard-error on invalid verdict: %v", err)
	}
	if _, ok := got["sim-1"]; ok {
		t.Errorf("invalid verdict should be absent from map, got %+v", got)
	}
}

func TestReviewPropagatesRunnerError(t *testing.T) {
	cr := &captureRunner{err: errors.New("boom"), stderr: "command not found"}
	r := newReviewerForTest(AgentClaude, cr.run)
	if _, _, err := r.Review(context.Background(), findings("sim-1")); err == nil {
		t.Fatal("expected error from runner failure")
	}
}

func TestReviewEmptyBatch(t *testing.T) {
	cr := &captureRunner{}
	r := newReviewerForTest(AgentClaude, cr.run)
	got, _, err := r.Review(context.Background(), nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty batch should no-op: got=%v err=%v", got, err)
	}
	if cr.bin != "" {
		t.Error("empty batch must not invoke the CLI")
	}
}

func TestNewCLIReviewerUnknownAgent(t *testing.T) {
	if _, err := NewCLIReviewer("gemini", "", "", 0, false, "", nil); err == nil {
		t.Fatal("expected error for unknown agent")
	}
}
