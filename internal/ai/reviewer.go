// Package ai defines the finding reviewer abstraction and a CLI-agent-backed
// implementation. The reviewer decides whether a SAST finding is a true or false
// positive, with a confidence and explanation.
package ai

import (
	"context"
	"fmt"
)

// Verdict classifications returned by the model.
const (
	VerdictTruePositive  = "TRUE_POSITIVE"
	VerdictFalsePositive = "FALSE_POSITIVE"
)

// NodeContext is one data-flow node plus its resolved source snippet.
type NodeContext struct {
	Order     int // 1-based position in the source→sink path
	FileName  string
	Line      int
	Name      string // the symbol/expression Checkmarx flagged
	Method    string
	Snippet   string // numbered source lines, or a note if unresolved
	StartLine int    // first source line in Snippet (for dedup)
	EndLine   int    // last source line in Snippet (for dedup)
	Resolved  bool
}

// Finding is the evidence handed to the reviewer for a single result.
type Finding struct {
	ID          string // stable identifier (the result's similarityID)
	QueryName   string
	Group       string
	Language    string
	Severity    string
	Description string
	Nodes       []NodeContext
}

// Verdict is the model's judgment on a finding. ID ties a verdict back to its
// finding when several are reviewed in one batch.
type Verdict struct {
	ID          string  `json:"id"`
	Verdict     string  `json:"verdict"`     // TRUE_POSITIVE or FALSE_POSITIVE
	Confidence  float64 `json:"confidence"`  // 0..1
	Explanation string  `json:"explanation"` // human-readable rationale
}

// IsFalsePositive reports whether the verdict is a false positive.
func (v Verdict) IsFalsePositive() bool { return v.Verdict == VerdictFalsePositive }

// Usage is the token spend and cost reported for one or more agent invocations.
// Cost and token counts come straight from the agent CLI when it reports them
// (the Claude CLI does; Copilot reports nothing, leaving Usage zero).
type Usage struct {
	InputTokens              int
	OutputTokens             int
	CacheCreationInputTokens int
	CacheReadInputTokens     int
	CostUSD                  float64
}

// TotalTokens is the sum of all token counters.
func (u Usage) TotalTokens() int {
	return u.InputTokens + u.OutputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
}

// Add accumulates o into u.
func (u *Usage) Add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheCreationInputTokens += o.CacheCreationInputTokens
	u.CacheReadInputTokens += o.CacheReadInputTokens
	u.CostUSD += o.CostUSD
}

// Reviewer judges a batch of findings in a single agent invocation, returning
// verdicts keyed by Finding.ID plus the token/cost usage the agent reported.
// Findings the agent omitted or answered unparseably are simply absent from the
// map; the caller decides how to recover. A non-nil error indicates a hard
// invocation failure (the whole batch failed).
type Reviewer interface {
	Review(ctx context.Context, findings []Finding) (map[string]Verdict, Usage, error)
}

// normalize validates and clamps a verdict produced by an agent.
func normalize(v Verdict) (Verdict, error) {
	switch v.Verdict {
	case VerdictTruePositive, VerdictFalsePositive:
	default:
		return Verdict{}, fmt.Errorf("invalid verdict %q", v.Verdict)
	}
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v, nil
}
