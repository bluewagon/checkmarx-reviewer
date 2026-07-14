package checkmarx

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testTenant = "test-tenant"

// newTestServer returns an httptest server with a handler and a Client pointed at it.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New(Options{BaseURI: srv.URL, Tenant: testTenant, APIKey: "refresh-token-xyz", HTTPClient: srv.Client()})
	return srv, c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestAccessTokenExchangeAndCaching(t *testing.T) {
	tokenPath := "/auth/realms/" + testTenant + "/protocol/openid-connect/token"
	var tokenCalls int

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case tokenPath:
			tokenCalls++
			body, _ := io.ReadAll(r.Body)
			form := string(body)
			if !strings.Contains(form, "grant_type=refresh_token") ||
				!strings.Contains(form, "client_id=ast-app") ||
				!strings.Contains(form, "refresh_token=refresh-token-xyz") {
				t.Errorf("unexpected token form: %s", form)
			}
			writeJSON(w, tokenResponse{AccessToken: "access-123", ExpiresIn: 600})
		case "/api/scans/scan-1":
			if got := r.Header.Get("Authorization"); got != "Bearer access-123" {
				t.Errorf("missing/incorrect bearer: %q", got)
			}
			writeJSON(w, Scan{ID: "scan-1", ProjectID: "proj-1"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	ctx := context.Background()
	if _, err := c.GetScan(ctx, "scan-1"); err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if _, err := c.GetScan(ctx, "scan-1"); err != nil {
		t.Fatalf("GetScan (2nd): %v", err)
	}
	if tokenCalls != 1 {
		t.Errorf("expected token exchanged once (cached), got %d", tokenCalls)
	}
}

func TestGetScanNoProjectID(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		writeJSON(w, Scan{ID: "scan-1"}) // no projectId
	})
	if _, err := c.GetScan(context.Background(), "scan-1"); err == nil {
		t.Fatal("expected error when scan has no projectId")
	}
}

func TestListHighToVerifyPagination(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		q := r.URL.Query()
		if q.Get("severity") != SeverityHigh || q.Get("state") != StateToVerify || q.Get("scan-id") != "scan-1" {
			t.Errorf("unexpected query: %v", q)
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		total := resultsPageSize + 5
		var page sastResultsResponse
		page.TotalCount = total
		if offset == 0 {
			page.Results = makeResults(resultsPageSize, 0)
		} else if offset == resultsPageSize {
			page.Results = makeResults(5, resultsPageSize)
		}
		writeJSON(w, page)
	})

	got, err := c.ListHighToVerify(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("ListHighToVerify: %v", err)
	}
	if len(got) != resultsPageSize+5 {
		t.Fatalf("expected %d results, got %d", resultsPageSize+5, len(got))
	}
	if got[0].SimilarityID != 0 || got[resultsPageSize].SimilarityID != SimilarityID(resultsPageSize) {
		t.Errorf("results not assembled in order: first=%d pageBoundary=%d", got[0].SimilarityID, got[resultsPageSize].SimilarityID)
	}
}

func TestSimilarityIDDecodesNumberOrString(t *testing.T) {
	cases := map[string]SimilarityID{
		`{"similarityID": 1234567890}`:   1234567890, // bare JSON number
		`{"similarityID": "1234567890"}`: 1234567890, // quoted numeric string
		`{"similarityID": -42}`:          -42,        // negative number
		`{"similarityID": "-42"}`:        -42,        // negative in a string
		`{"similarityID": null}`:         0,          // null -> 0
		`{"similarityID": ""}`:           0,          // empty string -> 0
		`{}`:                             0,          // absent -> 0
	}
	for body, want := range cases {
		var r Result
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Errorf("Unmarshal(%s): %v", body, err)
			continue
		}
		if r.SimilarityID != want {
			t.Errorf("Unmarshal(%s) similarityID = %d, want %d", body, r.SimilarityID, want)
		}
	}

	// A non-numeric string is a hard error.
	var r Result
	if err := json.Unmarshal([]byte(`{"similarityID":"abc"}`), &r); err == nil {
		t.Error("expected error decoding non-numeric similarityID")
	}
}

func makeResults(n, base int) []Result {
	out := make([]Result, n)
	for i := range out {
		out[i] = Result{SimilarityID: SimilarityID(base + i), Severity: SeverityHigh, State: StateToVerify}
	}
	return out
}

func TestGetPredicateHistory(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/sast-results-predicates/sim-1") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("project-ids"); got != "proj-1" {
			t.Errorf("project-ids = %q", got)
		}
		resp := predicateHistoryResponse{}
		resp.PredicateHistoryPerProject = append(resp.PredicateHistoryPerProject, struct {
			ProjectID  string      `json:"projectId"`
			Predicates []Predicate `json:"predicates"`
		}{ProjectID: "proj-1", Predicates: []Predicate{{Comment: "[AI-REVIEW] FALSE POSITIVE"}}})
		// A different project's predicates must be ignored.
		resp.PredicateHistoryPerProject = append(resp.PredicateHistoryPerProject, struct {
			ProjectID  string      `json:"projectId"`
			Predicates []Predicate `json:"predicates"`
		}{ProjectID: "other", Predicates: []Predicate{{Comment: "unrelated"}}})
		writeJSON(w, resp)
	})

	preds, err := c.GetPredicateHistory(context.Background(), "sim-1", "proj-1")
	if err != nil {
		t.Fatalf("GetPredicateHistory: %v", err)
	}
	if len(preds) != 1 || !strings.HasPrefix(preds[0].Comment, "[AI-REVIEW]") {
		t.Fatalf("expected only proj-1 predicate, got %+v", preds)
	}
}

func TestPostPredicateBody(t *testing.T) {
	var captured []predicateRequest
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/sast-results-predicates" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := c.PostPredicate(context.Background(), "sim-1", "proj-1", SeverityHigh, StateProposedNotExploitable, "hello")
	if err != nil {
		t.Fatalf("PostPredicate: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1-element array body, got %d", len(captured))
	}
	got := captured[0]
	want := predicateRequest{SimilarityID: "sim-1", ProjectID: "proj-1", Severity: SeverityHigh, State: StateProposedNotExploitable, Comment: "hello"}
	if got != want {
		t.Errorf("body = %+v, want %+v", got, want)
	}
}

func TestErrorStatusPropagates(t *testing.T) {
	// 404 is non-retryable, so this exercises the immediate-failure path.
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		http.Error(w, "no such scan", http.StatusNotFound)
	})
	if _, err := c.GetScan(context.Background(), "scan-1"); err == nil {
		t.Fatal("expected error on 404 response")
	}
}

func TestTransientStatusIsRetried(t *testing.T) {
	var apiCalls int
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		apiCalls++
		if apiCalls == 1 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		writeJSON(w, Scan{ID: "scan-1", ProjectID: "proj-1"})
	})
	c.retryBackoff = time.Millisecond

	scan, err := c.GetScan(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("GetScan should succeed after retry: %v", err)
	}
	if scan.ProjectID != "proj-1" || apiCalls != 2 {
		t.Errorf("scan=%+v apiCalls=%d, want proj-1 after 2 calls", scan, apiCalls)
	}
}

func TestRetryExhaustionFails(t *testing.T) {
	var apiCalls int
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		apiCalls++
		http.Error(w, "still broken", http.StatusServiceUnavailable)
	})
	c.retryBackoff = time.Millisecond

	if _, err := c.GetScan(context.Background(), "scan-1"); err == nil {
		t.Fatal("expected error once retries are exhausted")
	}
	if apiCalls != 3 {
		t.Errorf("apiCalls = %d, want 3 (initial + 2 retries)", apiCalls)
	}
}

func TestPostRetryResendsBody(t *testing.T) {
	var bodies []string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeJSON(w, tokenResponse{AccessToken: "t", ExpiresIn: 600})
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if len(bodies) == 1 {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c.retryBackoff = time.Millisecond

	err := c.PostPredicate(context.Background(), "sim-1", "proj-1", SeverityHigh, StateToVerify, "hello")
	if err != nil {
		t.Fatalf("PostPredicate should succeed after retry: %v", err)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || !strings.Contains(bodies[1], `"sim-1"`) {
		t.Errorf("retried POST must resend the identical body, got %q", bodies)
	}
}
