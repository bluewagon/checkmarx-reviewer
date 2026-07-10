package checkmarx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SimilarityID is a Checkmarx result's similarity identifier. Different Checkmarx
// One versions encode it either as a JSON number or as a quoted string, so it
// unmarshals from both forms (and from null/empty, which becomes 0).
type SimilarityID int64

// UnmarshalJSON accepts a JSON number, a quoted numeric string, or null.
func (s *SimilarityID) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*s = 0
		return nil
	}
	// Unwrap a quoted string form ("12345") to its inner value.
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		if str = strings.TrimSpace(str); str == "" {
			*s = 0
			return nil
		}
		data = []byte(str)
	}
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return fmt.Errorf("similarityID %s: %w", data, err)
	}
	*s = SimilarityID(n)
	return nil
}

// String renders the identifier as a base-10 string, as the predicates API and
// report expect it.
func (s SimilarityID) String() string { return strconv.FormatInt(int64(s), 10) }

// Result state values used by the SAST results and predicates APIs.
const (
	StateToVerify               = "TO_VERIFY"
	StateNotExploitable         = "NOT_EXPLOITABLE"
	StateProposedNotExploitable = "PROPOSED_NOT_EXPLOITABLE"
	StateConfirmed              = "CONFIRMED"
	StateUrgent                 = "URGENT"
)

// Severity values.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
)

// Scan is the subset of GET /api/scans/{id} we need.
type Scan struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectId"`
	Status    string `json:"status"`
	Branch    string `json:"branch"`
}

// Node is a single element of a SAST result's source→sink data-flow path.
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FileName string `json:"fileName"`
	FullName string `json:"fullName"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Method   string `json:"method"`
	Length   int    `json:"length"`
}

// ResultData carries the query metadata and data-flow nodes for a result.
type ResultData struct {
	QueryID      any    `json:"queryId"`
	QueryName    string `json:"queryName"`
	Group        string `json:"group"`
	LanguageName string `json:"languageName"`
	ResultHash   string `json:"resultHash"`
	Nodes        []Node `json:"nodes"`
}

// Result is a single SAST finding from GET /api/sast-results.
type Result struct {
	Type            string       `json:"type"`
	ID              string       `json:"id"`
	SimilarityID    SimilarityID `json:"similarityID"`
	ResultHash      string       `json:"resultHash"`
	Status          string       `json:"status"`
	State           string       `json:"state"`
	Severity        string       `json:"severity"`
	ConfidenceLevel int          `json:"confidenceLevel"`
	Description     string       `json:"description"`
	Data            ResultData   `json:"data"`
}

// sastResultsResponse is the envelope returned by GET /api/sast-results.
type sastResultsResponse struct {
	Results    []Result `json:"results"`
	TotalCount int      `json:"totalCount"`
}

// Predicate is one entry in a result's triage history.
type Predicate struct {
	SimilarityID string `json:"similarityId"`
	ProjectID    string `json:"projectId"`
	State        string `json:"state"`
	Severity     string `json:"severity"`
	Comment      string `json:"comment"`
	CreatedBy    string `json:"createdBy"`
	CreatedAt    string `json:"createdAt"`
}

// predicateHistoryResponse is the envelope from GET /api/sast-results-predicates/{similarityId}.
type predicateHistoryResponse struct {
	PredicateHistoryPerProject []struct {
		ProjectID  string      `json:"projectId"`
		Predicates []Predicate `json:"predicates"`
	} `json:"predicateHistoryPerProject"`
}

// predicateRequest is one element of the POST /api/sast-results-predicates array body.
type predicateRequest struct {
	SimilarityID string `json:"similarityId"`
	ProjectID    string `json:"projectId"`
	Severity     string `json:"severity"`
	State        string `json:"state"`
	Comment      string `json:"comment"`
}
