package checkmarx

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
)

// resultsPageSize is the per-request page size for listing SAST results.
const resultsPageSize = 100

// ListHighToVerify returns all HIGH severity, TO_VERIFY state SAST results for a
// scan, following pagination until the full set is retrieved.
func (c *Client) ListHighToVerify(ctx context.Context, scanID string) ([]Result, error) {
	var all []Result
	offset := 0

	for {
		q := url.Values{}
		q.Set("scan-id", scanID)
		q.Set("severity", SeverityHigh)
		q.Set("state", StateToVerify)
		q.Set("limit", strconv.Itoa(resultsPageSize))
		q.Set("offset", strconv.Itoa(offset))

		var page sastResultsResponse
		if err := c.doJSON(ctx, http.MethodGet, "/api/sast-results", q, nil, "", &page); err != nil {
			return nil, err
		}

		c.log.Debug("sast-results page", "scanId", scanID, "offset", offset,
			"returned", len(page.Results), "totalCount", page.TotalCount)
		logResultAnomalies(c.log, page.Results)

		all = append(all, page.Results...)

		offset += len(page.Results)
		if len(page.Results) < resultsPageSize || offset >= page.TotalCount {
			break
		}
	}

	return all, nil
}

// logResultAnomalies warns about results missing the data the AI review depends
// on (query name, source→sink data-flow nodes), so an API response that omits
// them is visible per result rather than surfacing later as a confused verdict.
func logResultAnomalies(log *slog.Logger, results []Result) {
	for _, r := range results {
		if r.Data.QueryName == "" || len(r.Data.Nodes) == 0 {
			log.Warn("sast result missing data",
				"resultId", r.ID,
				"similarityId", r.SimilarityID.String(),
				"queryName", r.Data.QueryName,
				"nodes", len(r.Data.Nodes),
				"status", r.Status,
				"state", r.State)
		}
	}
}
