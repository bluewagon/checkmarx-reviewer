package checkmarx

import (
	"context"
	"fmt"
	"net/http"
)

// GetScan fetches a scan by ID, primarily to resolve its projectId.
func (c *Client) GetScan(ctx context.Context, scanID string) (*Scan, error) {
	var scan Scan
	if err := c.doJSON(ctx, http.MethodGet, "/api/scans/"+scanID, nil, nil, "", &scan); err != nil {
		return nil, err
	}
	if scan.ProjectID == "" {
		return nil, fmt.Errorf("scan %s returned no projectId", scanID)
	}
	return &scan, nil
}
