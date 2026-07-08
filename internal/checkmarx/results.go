package checkmarx

import (
	"context"
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

		all = append(all, page.Results...)

		offset += len(page.Results)
		if len(page.Results) < resultsPageSize || offset >= page.TotalCount {
			break
		}
	}

	return all, nil
}
