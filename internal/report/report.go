// Package report defines the structured JSON output written after a review run.
package report

import (
	"encoding/json"
	"os"
	"time"
)

// Action describes what the tool did (or would do) for a finding.
const (
	ActionCommented          = "COMMENTED"                // comment posted, state unchanged
	ActionProposedNotExploit = "PROPOSED_NOT_EXPLOITABLE" // comment posted + state changed
	ActionSkippedAlreadyDone = "SKIPPED_ALREADY_REVIEWED" // prior AI comment found
	ActionSkippedBudget      = "SKIPPED_COST_LIMIT"       // run stopped: cost limit reached
	ActionError              = "ERROR"                    // per-finding failure
)

// FindingResult records the outcome for one finding.
type FindingResult struct {
	SimilarityID  string  `json:"similarityId"`
	ResultHash    string  `json:"resultHash,omitempty"`
	QueryName     string  `json:"queryName"`
	Severity      string  `json:"severity"`
	SinkFile      string  `json:"sinkFile,omitempty"`
	SinkLine      int     `json:"sinkLine,omitempty"`
	Verdict       string  `json:"verdict,omitempty"`
	Confidence    float64 `json:"confidence,omitempty"`
	Explanation   string  `json:"explanation,omitempty"`
	Action        string  `json:"action"`
	StateSet      string  `json:"stateSet,omitempty"`
	NodesTotal    int     `json:"nodesTotal"`
	NodesResolved int     `json:"nodesResolved"`
	CommentPosted bool    `json:"commentPosted"`
	Error         string  `json:"error,omitempty"`
}

// Report is the top-level run summary.
type Report struct {
	ScanID         string    `json:"scanId"`
	ProjectID      string    `json:"projectId"`
	Agent          string    `json:"agent"`
	Model          string    `json:"model,omitempty"`
	BatchSize      int       `json:"batchSize"`
	Concurrency    int       `json:"concurrency"`
	FPThreshold    float64   `json:"fpConfidenceThreshold"`
	DryRun         bool      `json:"dryRun"`
	GeneratedAt    time.Time `json:"generatedAt"`
	TotalFindings  int       `json:"totalFindings"`
	Reviewed       int       `json:"reviewed"`
	Skipped        int       `json:"skipped"`
	Errors         int       `json:"errors"`
	TruePositives  int       `json:"truePositives"`
	FalsePositives int       `json:"falsePositives"`
	StateChanges   int       `json:"stateChanges"`

	// Token spend and cost accounting for the run.
	InputTokens      int     `json:"inputTokens"`
	OutputTokens     int     `json:"outputTokens"`
	TotalTokens      int     `json:"totalTokens"`
	EstimatedCostUSD float64 `json:"estimatedCostUsd"`
	CostLimitUSD     float64 `json:"costLimitUsd,omitempty"`
	Aborted          bool    `json:"aborted,omitempty"`
	AbortReason      string  `json:"abortReason,omitempty"`

	Findings []FindingResult `json:"findings"`
}

// WriteJSON writes the report as indented JSON to path.
func WriteJSON(path string, r *Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
