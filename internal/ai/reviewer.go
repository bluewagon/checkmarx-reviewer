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
	Order    int // 1-based position in the source→sink path
	FileName string
	Line     int
	Name     string // the symbol/expression Checkmarx flagged
	Method   string
	Snippet  string // numbered source lines, or a note if unresolved
	Resolved bool
}

// Finding is the evidence handed to the reviewer for a single result.
type Finding struct {
	QueryName   string
	Group       string
	Language    string
	Severity    string
	Description string
	Nodes       []NodeContext
}

// Verdict is the model's judgment on a finding.
type Verdict struct {
	Verdict     string  `json:"verdict"`     // TRUE_POSITIVE or FALSE_POSITIVE
	Confidence  float64 `json:"confidence"`  // 0..1
	Explanation string  `json:"explanation"` // human-readable rationale
}

// IsFalsePositive reports whether the verdict is a false positive.
func (v Verdict) IsFalsePositive() bool { return v.Verdict == VerdictFalsePositive }

// Reviewer judges a single finding. Implementations must be safe for sequential
// use; the orchestrator calls Review once per finding.
type Reviewer interface {
	Review(ctx context.Context, f Finding) (Verdict, error)
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
