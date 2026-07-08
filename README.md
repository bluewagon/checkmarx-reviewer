# checkmarx-reviewer

An AI triage assistant for **Checkmarx One** SAST findings.

For a single scan, it reviews every **HIGH** severity finding in the **To Verify**
state, reads the actual source code along each finding's source→sink data-flow path
from a local checkout, and asks a Claude model whether the finding is a **true
positive** or **false positive** — with an explanation and a confidence level. It then:

- posts the verdict as a comment on **every** reviewed finding, and
- automatically sets the finding's state to **Proposed Not Exploitable** when the model
  is a **high-confidence false positive** (configurable threshold),

leaving a human only to confirm rather than investigate from scratch.

## How it works

```
scan-id ──▶ GET /api/scans/{id}            → projectId
        ──▶ GET /api/sast-results          → HIGH + TO_VERIFY findings (paginated)
   per finding:
        ──▶ GET /api/sast-results-predicates/{similarityId}   → skip if already reviewed
        ──▶ read source snippets along the data-flow nodes (local checkout)
        ──▶ Claude (forced `submit_verdict` tool) → {verdict, confidence, explanation}
        ──▶ POST /api/sast-results-predicates → comment (+ state if high-confidence FP)
   ──▶ write JSON report
```

Findings already carrying an `[AI-REVIEW]` comment are **skipped**, so re-runs are
idempotent.

## Requirements

- Go 1.26+
- A Checkmarx One API key with permission to read results and update result state
  (specifically *Update-result-state-propose-not-exploitable* for the auto state change).
- An Anthropic API key.
- A **local checkout of the scanned code at the scanned commit** — the tool reads files
  by the paths Checkmarx reports, relative to `--repo-path`.

## Configuration

Connection settings come from the environment (see [.env.example](.env.example)):

| Variable | Required | Description |
|----------|----------|-------------|
| `CX_APIKEY` | yes | Checkmarx One API key (OAuth refresh token) |
| `CX_BASE_URI` | yes | Region API base URL, e.g. `https://us.ast.checkmarx.net` |
| `CX_TENANT` | yes | Checkmarx One tenant name |
| `ANTHROPIC_API_KEY` | yes | Anthropic API key |
| `CX_AI_MODEL` | no | Default model id (overridden by `--model`) |

## Usage

```bash
go build -o checkmarx-reviewer .

# Preview only — computes verdicts and intended actions, writes the report,
# but makes NO changes in Checkmarx:
./checkmarx-reviewer \
  --scan-id 1a2b3c4d-... \
  --repo-path /path/to/checkout \
  --dry-run

# Live run:
./checkmarx-reviewer --scan-id 1a2b3c4d-... --repo-path /path/to/checkout
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-id` | (required) | Scan to review |
| `--repo-path` | (required) | Local checkout matching the scanned commit |
| `--model` | `claude-opus-4-8` | Claude model id |
| `--fp-confidence-threshold` | `0.90` | Min confidence [0-1] to auto-set Proposed Not Exploitable |
| `--context-lines` | `8` | Source lines of context around each data-flow node |
| `--report` | `checkmarx-ai-review.json` | Output report path |
| `--dry-run` | `false` | Compute everything, write nothing to Checkmarx |

The process exits non-zero if any finding failed during review (useful for pipelines).

## Output

A JSON report (`--report`) with run totals and a per-finding record: verdict,
confidence, explanation, action taken (`COMMENTED` / `PROPOSED_NOT_EXPLOITABLE` /
`SKIPPED_ALREADY_REVIEWED` / `ERROR`), and how many data-flow nodes had their source
resolved (so path mismatches against `--repo-path` are visible).

### Comment format posted to Checkmarx

```
[AI-REVIEW] FALSE POSITIVE — confidence 92%
<explanation>
—
model=claude-opus-4-8 · reviewed 2026-07-08 · checkmarx-reviewer
```

## Development

```bash
go test ./...
go vet ./...
```

### Layout

```
main.go                    flags, wiring, exit code
internal/config            flag + env parsing and validation
internal/checkmarx         Checkmarx One REST client (auth, scans, results, predicates)
internal/source            local source-snippet extraction
internal/ai                Reviewer interface + Anthropic (forced-tool) implementation
internal/review            the orchestration pipeline
internal/report            JSON report model + writer
```

## Notes & assumptions

- **Auth** uses the standard `ast-app` public client with the refresh-token grant. If
  your tenant uses an OAuth client id/secret instead, the token exchange in
  `internal/checkmarx/client.go` needs adjusting.
- **Source paths**: node `fileName` values are treated as repo-root-relative to
  `--repo-path`. Files that don't resolve are reported (not fatal) and the affected
  nodes are sent to the model marked as unavailable.
- **Engine scope**: SAST only.
```
