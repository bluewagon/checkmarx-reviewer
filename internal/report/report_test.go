package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteJSONRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	in := &Report{
		ScanID:         "scan-1",
		ProjectID:      "proj-1",
		Model:          "claude-opus-4-8",
		FPThreshold:    0.9,
		DryRun:         true,
		GeneratedAt:    time.Now().UTC().Truncate(time.Second),
		TotalFindings:  2,
		Reviewed:       1,
		Skipped:        1,
		FalsePositives: 1,
		StateChanges:   1,
		Findings: []FindingResult{
			{SimilarityID: "sim-1", QueryName: "SQL_Injection", Severity: "HIGH", Verdict: "FALSE_POSITIVE",
				Confidence: 0.95, Action: ActionProposedNotExploit, StateSet: "PROPOSED_NOT_EXPLOITABLE",
				NodesTotal: 3, NodesResolved: 3, CommentPosted: false},
			{SimilarityID: "sim-2", QueryName: "XSS", Severity: "HIGH", Action: ActionSkippedAlreadyDone},
		},
	}

	if err := WriteJSON(path, in); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ScanID != in.ScanID || out.TotalFindings != 2 || len(out.Findings) != 2 {
		t.Errorf("round trip mismatch: %+v", out)
	}
	if out.Findings[0].Action != ActionProposedNotExploit || out.Findings[0].Confidence != 0.95 {
		t.Errorf("finding[0] mismatch: %+v", out.Findings[0])
	}
	if out.Findings[1].Action != ActionSkippedAlreadyDone {
		t.Errorf("finding[1] action = %s", out.Findings[1].Action)
	}
}
