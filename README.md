# checkmarx-reviewer

An AI triage assistant for **Checkmarx One** SAST findings.

For a single scan, it reviews every **HIGH** severity finding in the **To Verify**
state, reads the actual source code along each finding's source→sink data-flow path
from a local checkout, and asks an **AI agent CLI** — either **Claude Code** (`claude`)
or **GitHub Copilot** (`copilot`) — whether the finding is a **true positive** or
**false positive**, with an explanation and a confidence level. It then:

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
        ──▶ agent CLI (claude | copilot) → {verdict, confidence, explanation} JSON
        ──▶ POST /api/sast-results-predicates → comment (+ state if high-confidence FP)
   ──▶ write JSON report
```

Findings already carrying an `[AI-REVIEW]` comment are **skipped**, so re-runs are
idempotent.

## Requirements

- Go 1.26+
- A Checkmarx One API key with permission to read results and update result state
  (specifically *Update-result-state-propose-not-exploitable* for the auto state change).
- **One of the supported agent CLIs, installed and already authenticated:**
  - [Claude Code](https://docs.claude.com/en/docs/claude-code) — the `claude` command, or
  - [GitHub Copilot CLI](https://docs.github.com/copilot) — the `copilot` command.

  This tool shells out to the agent; **the agent handles its own model
  authentication** (`claude` login / `gh`/Copilot auth). No model API key is read by
  this tool.
- A **local checkout of the scanned code at the scanned commit** — the tool reads files
  by the paths Checkmarx reports, relative to `--repo-path`.

## Configuration

Checkmarx connection settings come from the environment (see [.env.example](.env.example)):

| Variable | Required | Description |
|----------|----------|-------------|
| `CX_APIKEY` | yes | Checkmarx One API key (OAuth refresh token) |
| `CX_BASE_URI` | yes | Region API base URL, e.g. `https://us.ast.checkmarx.net` |
| `CX_TENANT` | yes | Checkmarx One tenant name |
| `CX_AI_AGENT` | no | Default agent (`claude` \| `copilot`); overridden by `--agent` |
| `CX_AI_MODEL` | no | Default model id; overridden by `--model` |
| `CX_AI_AGENT_BIN` | no | Override the agent binary name/path; overridden by `--agent-bin` |

## Usage

```bash
go build -o checkmarx-reviewer .

# Preview only — computes verdicts and intended actions, writes the report,
# but makes NO changes in Checkmarx (default agent: claude):
./checkmarx-reviewer \
  --scan-id 1a2b3c4d-... \
  --repo-path /path/to/checkout \
  --dry-run

# Live run using GitHub Copilot instead of Claude:
./checkmarx-reviewer --scan-id 1a2b3c4d-... --repo-path /path/to/checkout --agent copilot
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-id` | (required) | Scan to review |
| `--repo-path` | (required) | Local checkout matching the scanned commit |
| `--agent` | `claude` | AI agent CLI: `claude` or `copilot` |
| `--model` | (agent default) | Model id passed to the agent (`claude` defaults to `claude-opus-4-8`; `copilot` uses its configured default) |
| `--agent-bin` | (agent's command) | Override the agent binary name/path |
| `--agent-timeout` | `180` | Per-finding agent timeout, in seconds |
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
via=claude (claude-opus-4-8) · reviewed 2026-07-08 · checkmarx-reviewer
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
internal/ai                Reviewer interface + CLI-agent (claude/copilot) implementation
internal/review            the orchestration pipeline
internal/report            JSON report model + writer
```

## Notes & assumptions

- **Checkmarx auth** uses the standard `ast-app` public client with the refresh-token
  grant. If your tenant uses an OAuth client id/secret instead, the token exchange in
  `internal/checkmarx/client.go` needs adjusting.
- **Agent auth** is out of scope for this tool — the `claude` / `copilot` CLI must
  already be installed and logged in. The tool only shells out and parses the reply.
- **Agent invocation** (in `internal/ai/cli.go`):
  - `claude` is run as `claude -p --output-format json [--model M]` with the prompt on
    stdin; the JSON envelope's `result` field is unwrapped.
  - `copilot` is run as `copilot [--model M] --allow-all-tools -p "<prompt>"`.
  - The agent is asked to return a single JSON verdict object; the parser tolerates
    surrounding prose or code fences and rejects malformed/invalid verdicts (recorded
    as `ERROR` in the report). Adjust the `agentSpecs` table if your CLI version uses
    different flags, or point `--agent-bin` at a wrapper.
- **Source paths**: node `fileName` values are treated as repo-root-relative to
  `--repo-path`. Files that don't resolve are reported (not fatal) and the affected
  nodes are sent to the agent marked as unavailable.
- **Engine scope**: SAST only.
```
