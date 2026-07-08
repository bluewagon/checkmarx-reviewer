package ai

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestExtractVerdictPureJSON(t *testing.T) {
	v, err := extractVerdict(`{"verdict":"TRUE_POSITIVE","confidence":0.8,"explanation":"x"}`)
	if err != nil {
		t.Fatalf("extractVerdict: %v", err)
	}
	if v.Verdict != VerdictTruePositive || v.Confidence != 0.8 {
		t.Errorf("got %+v", v)
	}
}

func TestExtractVerdictFromProseAndFences(t *testing.T) {
	text := "Sure, here is my analysis.\n\n```json\n{\"verdict\": \"FALSE_POSITIVE\", \"confidence\": 0.91, \"explanation\": \"input is validated\"}\n```\nHope that helps!"
	v, err := extractVerdict(text)
	if err != nil {
		t.Fatalf("extractVerdict: %v", err)
	}
	if !v.IsFalsePositive() || v.Confidence != 0.91 {
		t.Errorf("got %+v", v)
	}
}

func TestExtractVerdictPicksLastVerdictObject(t *testing.T) {
	// An unrelated JSON object precedes the real verdict; braces inside strings
	// must not confuse the scanner.
	text := `{"note":"contains } brace"} then {"verdict":"TRUE_POSITIVE","confidence":1,"explanation":"reaches sink { unsanitized"}`
	v, err := extractVerdict(text)
	if err != nil {
		t.Fatalf("extractVerdict: %v", err)
	}
	if v.Verdict != VerdictTruePositive {
		t.Errorf("got %+v", v)
	}
}

func TestExtractVerdictNoJSON(t *testing.T) {
	if _, err := extractVerdict("I cannot help with that."); err == nil {
		t.Fatal("expected error when no verdict JSON present")
	}
}

func TestExtractClaudeResultUnwrapsEnvelope(t *testing.T) {
	env := `{"type":"result","is_error":false,"result":"{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.9,\"explanation\":\"safe\"}"}`
	got := extractClaudeResult([]byte(env))
	if !strings.Contains(got, "FALSE_POSITIVE") {
		t.Fatalf("did not unwrap result: %q", got)
	}
	// Non-envelope input passes through.
	raw := `{"verdict":"TRUE_POSITIVE"}`
	if extractClaudeResult([]byte(raw)) != raw {
		t.Error("raw JSON should pass through unchanged")
	}
}

// captureRunner records how the CLI was invoked and returns a canned response.
type captureRunner struct {
	bin    string
	args   []string
	stdin  string
	stdout string
	stderr string
	err    error
}

func (c *captureRunner) run(_ context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, error) {
	c.bin, c.args, c.stdin = bin, args, string(stdin)
	return []byte(c.stdout), []byte(c.stderr), c.err
}

func newReviewerForTest(agent string, run runner) *CLIReviewer {
	spec := agentSpecs[agent]
	return &CLIReviewer{agent: agent, spec: spec, bin: spec.bin, model: spec.defaultModel, timeout: time.Second, run: run}
}

func sampleFinding() Finding {
	return Finding{QueryName: "SQL_Injection", Nodes: []NodeContext{{Order: 1, FileName: "a.go", Line: 1, Snippet: "1| x", Resolved: true}}}
}

func TestClaudeReviewSendsPromptOnStdin(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","is_error":false,"result":"{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.95,\"explanation\":\"validated\"}"}`}
	r := newReviewerForTest(AgentClaude, cr.run)

	v, err := r.Review(context.Background(), sampleFinding())
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !v.IsFalsePositive() || v.Confidence != 0.95 {
		t.Errorf("verdict = %+v", v)
	}
	if !strings.Contains(cr.stdin, "SQL_Injection") {
		t.Error("prompt should be sent on stdin for claude")
	}
	if !slices.Contains(cr.args, "--output-format") || !slices.Contains(cr.args, "claude-opus-4-8") {
		t.Errorf("claude args missing expected flags: %v", cr.args)
	}
}

func TestCopilotReviewSendsPromptAsArg(t *testing.T) {
	cr := &captureRunner{stdout: "Thinking...\nFinal: {\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.7,\"explanation\":\"reaches sink\"}\n"}
	r := newReviewerForTest(AgentCopilot, cr.run)

	v, err := r.Review(context.Background(), sampleFinding())
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if v.Verdict != VerdictTruePositive {
		t.Errorf("verdict = %+v", v)
	}
	if cr.stdin != "" {
		t.Error("copilot should not use stdin")
	}
	if len(cr.args) == 0 || !strings.Contains(cr.args[len(cr.args)-1], "SQL_Injection") {
		t.Errorf("copilot should receive prompt as final arg: %v", cr.args)
	}
	if !slices.Contains(cr.args, "--allow-all-tools") {
		t.Errorf("copilot args missing --allow-all-tools: %v", cr.args)
	}
}

func TestReviewPropagatesRunnerError(t *testing.T) {
	cr := &captureRunner{err: errors.New("boom"), stderr: "command not found"}
	r := newReviewerForTest(AgentClaude, cr.run)
	if _, err := r.Review(context.Background(), sampleFinding()); err == nil {
		t.Fatal("expected error from runner failure")
	}
}

func TestReviewInvalidVerdictRejected(t *testing.T) {
	cr := &captureRunner{stdout: `{"type":"result","result":"{\"verdict\":\"MAYBE\",\"confidence\":0.5,\"explanation\":\"x\"}"}`}
	r := newReviewerForTest(AgentClaude, cr.run)
	if _, err := r.Review(context.Background(), sampleFinding()); err == nil {
		t.Fatal("expected error for invalid verdict value")
	}
}

func TestNewCLIReviewerUnknownAgent(t *testing.T) {
	if _, err := NewCLIReviewer("gemini", "", "", 0); err == nil {
		t.Fatal("expected error for unknown agent")
	}
}
