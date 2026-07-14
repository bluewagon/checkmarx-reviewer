package checkmarx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// GetPredicateHistory returns the triage history for a result (identified by its
// similarityID) within a project, most-recent entries included. Used to detect
// whether we have already commented on a finding.
func (c *Client) GetPredicateHistory(ctx context.Context, similarityID, projectID string) ([]Predicate, error) {
	q := url.Values{}
	q.Set("project-ids", projectID)

	var resp predicateHistoryResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/sast-results-predicates/"+similarityID, q, nil, "", &resp); err != nil {
		return nil, err
	}

	var predicates []Predicate
	for _, group := range resp.PredicateHistoryPerProject {
		if group.ProjectID == projectID {
			predicates = append(predicates, group.Predicates...)
		}
	}
	return predicates, nil
}

// PostPredicate adds a triage predicate to a result: a comment plus a target
// state. To comment without changing state, pass the result's current state.
func (c *Client) PostPredicate(ctx context.Context, similarityID, projectID, severity, state, comment string) error {
	payload := []predicateRequest{{
		SimilarityID: similarityID,
		ProjectID:    projectID,
		Severity:     severity,
		State:        state,
		Comment:      comment,
	}}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return c.doJSON(ctx, http.MethodPost, "/api/sast-results-predicates", nil, body, "application/json", nil)
}
