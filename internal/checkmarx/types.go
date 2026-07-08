package checkmarx

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
	Type            string     `json:"type"`
	ID              string     `json:"id"`
	SimilarityID    string     `json:"similarityID"`
	ResultHash      string     `json:"resultHash"`
	Status          string     `json:"status"`
	State           string     `json:"state"`
	Severity        string     `json:"severity"`
	ConfidenceLevel int        `json:"confidenceLevel"`
	Description     string     `json:"description"`
	Data            ResultData `json:"data"`
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
