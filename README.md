# checkmarx-reviewer

An AI triage assistant for **Checkmarx One** SAST findings.

For a single scan, it reviews every **HIGH** severity finding in the **To Verify**
state, reads the actual source code along each finding's source→sink data-flow path
from a local checkout, and asks an **AI agent** — **Claude Code** (`claude`),
**GitHub Copilot CLI** (`copilot`), or the **Anthropic API directly** (`anthropic`,
no CLI required) — whether the finding is a **true positive** or **false positive**,
with an explanation and a confidence level. It then:

- posts the verdict as a comment on **every** reviewed finding, and
- automatically sets the finding's state to **Proposed Not Exploitable** when the model
  is a **high-confidence false positive** (configurable threshold),

leaving a human only to confirm rather than investigate from scratch.

## How it works

```
scan-id ──▶ GET /api/scans/{id}            → projectId
        ──▶ GET /api/sast-results          → HIGH + TO_VERIFY findings (paginated)
   per finding: GET /api/sast-results-predicates/{similarityId} → skip if already reviewed
                read source snippets along the data-flow nodes (local checkout)
   per BATCH of findings (default 20), up to --concurrency batches in parallel:
        ──▶ one agent call (claude | copilot | anthropic) → JSON array of {id, verdict, confidence, explanation}
            (any finding the batch drops/mangles is re-reviewed individually)
        ──▶ POST /api/sast-results-predicates → comment per finding (+ state if high-confidence FP)
   ──▶ write JSON report
```

Findings already carrying an `[AI-REVIEW]` comment are **skipped**, so re-runs are
idempotent. The run stops early once cumulative AI cost crosses `--cost-limit`
(findings reviewed so far still get their results; the run exits non-zero).

## Requirements

- Go 1.26+
- A Checkmarx One API key with permission to read results and update result state
  (specifically *Update-result-state-propose-not-exploitable* for the auto state change).
- **One of the supported agents:**
  - [Claude Code](https://docs.claude.com/en/docs/claude-code) — the `claude` command,
    installed and already authenticated,
  - [GitHub Copilot CLI](https://docs.github.com/copilot) — the `copilot` command,
    installed and already authenticated, or
  - **`anthropic`** — calls the Anthropic API directly, no CLI needed;
    authenticates via `ANTHROPIC_API_KEY` (or another standard Anthropic SDK
    credential source).

  For `claude`/`copilot` this tool shells out to the agent, which **handles its own
  model authentication**; no model API key is read by this tool for those two.
  `anthropic` calls the API directly and, with `--agentic-source`, runs its own
  sandboxed read-only tool loop (Read/Grep/Glob/LS scoped to `--repo-path`) instead
  of shelling out to a CLI.
- A **local checkout of the scanned code at the scanned commit**, or a **Bitbucket
  Data Center/Server clone or browse URL** passed as `--repo-path` (shallow-cloned
  on the fly using `--bitbucket-token`) — the tool reads files by the paths Checkmarx
  reports, relative to the resolved repo root.

## Configuration

Checkmarx connection settings come from the environment (see [.env.example](.env.example)):

| Variable | Required | Description |
|----------|----------|-------------|
| `CX_APIKEY` | yes | Checkmarx One API key (OAuth refresh token) |
| `CX_BASE_URI` | yes | Region API base URL, e.g. `https://us.ast.checkmarx.net` |
| `CX_TENANT` | yes | Checkmarx One tenant name |
| `CX_BITBUCKET_TOKEN` | only for a Bitbucket `--repo-path` URL | HTTP access token used to shallow-clone the repo |
| `CX_AI_AGENT` | no | Default agent (`claude` \| `copilot` \| `anthropic`); overridden by `--agent` |
| `ANTHROPIC_API_KEY` | only for the `anthropic` agent | Anthropic API key (other standard SDK credential sources also work) |
| `CX_AI_MODEL` | no | Default model id; overridden by `--model` |
| `CX_AI_AGENT_BIN` | no | Override the agent binary name/path; overridden by `--agent-bin` (ignored for `anthropic`) |
| `CX_AI_BATCH_SIZE` | no | Default `--batch-size` |
| `CX_CONCURRENCY` | no | Default `--concurrency` |
| `CX_AI_COST_LIMIT` | no | Default `--cost-limit` |
| `CX_AI_AGENTIC_SOURCE` | no | Default `--agentic-source` |
| `CX_VERBOSE` | no | Default `--verbose` |
| `CX_LOG_DIR` | no | Default `--log-dir` |

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

# Live run calling the Anthropic API directly (no CLI), with a cost cap and the
# agent allowed to read the repo directly instead of only inlined snippets:
./checkmarx-reviewer --scan-id 1a2b3c4d-... --repo-path /path/to/checkout \
  --agent anthropic --agentic-source --cost-limit 5.00

# repo-path can also be a Bitbucket DC/Server clone or browse URL, shallow-cloned
# on the fly (requires --bitbucket-token or $CX_BITBUCKET_TOKEN):
./checkmarx-reviewer --scan-id 1a2b3c4d-... \
  --repo-path https://bitbucket.example.com/projects/PROJ/repos/repo/browse
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-id` | (required) | Scan to review |
| `--repo-path` | (required) | Local checkout matching the scanned commit, or a Bitbucket clone/browse URL to shallow-clone |
| `--agent` | `claude` | AI agent: `claude`, `copilot`, or `anthropic` (direct API call, no CLI) |
| `--model` | (agent default) | Model id passed to the agent (`claude`/`anthropic` default to `claude-opus-4-8`; `copilot` uses its configured default) |
| `--agent-bin` | (agent's command) | Override the agent binary name/path (ignored for `anthropic`) |
| `--batch-size` | `20` | Findings reviewed per agent invocation (≥1); higher saves tokens |
| `--concurrency` | `4` | Max findings/batches processed in parallel (history fetches, agent calls, predicate posts); `1` = fully sequential |
| `--agent-timeout` | `600` | Per-invocation agent timeout, in seconds |
| `--fp-confidence-threshold` | `0.90` | Min confidence [0-1] to auto-set Proposed Not Exploitable |
| `--cost-limit` | `0` (no limit) | Stop the run once cumulative AI cost (USD) exceeds this; enforced for agents that report cost (`claude` CLI, `anthropic` API) |
| `--agentic-source` | `false` | Let the agent read/search the repo for extra context instead of only the inlined snippets (uses more time per finding) |
| `--context-lines` | `8` | Source lines of context around each data-flow node |
| `--report` | `checkmarx-ai-review.json` | Output report path |
| `--dry-run` | `false` | Compute everything, write nothing to Checkmarx |
| `--bitbucket-token` | `$CX_BITBUCKET_TOKEN` | Bitbucket HTTP access token, required when `--repo-path` is a URL |
| `--verbose` | `false` | Debug logging on stderr (HTTP requests, agent invocations) |
| `--log-dir` | `logs` | Directory for per-run diagnostics: a JSONL debug log plus raw Checkmarx responses, AI prompts, and AI output. `off` disables |

The process exits non-zero if any finding failed during review, or if the run was
aborted early (cost limit or cancellation) — useful for pipelines.

### Token cost & batching

Each agent invocation re-injects the agent's own system prompt and tool schemas — a
large fixed overhead for `claude`/`copilot`. Reviewing findings **in batches**
(`--batch-size`, default 20) pays that overhead once per batch instead of once per
finding, which is the dominant cost lever; within a finding, overlapping source
snippets are also collapsed. To protect the auto state-change, any finding a batch
drops or answers unparseably is **re-reviewed individually** before being marked an
error. Set `--batch-size 1` to disable batching (one finding per call), or raise it
to trade a little per-finding reasoning sharpness for lower cost.

`--concurrency` (default 4) runs multiple batches in parallel to cut wall-clock time
on large scans; with `--concurrency` > 1 the `--cost-limit` boundary becomes
approximate, since batches already in flight when the limit is hit still complete.

## Output

A JSON report (`--report`) with run totals — including token usage and estimated
cost, and whether the run `Aborted` early (cost limit or cancellation, with
`AbortReason`) — and a per-finding record: verdict, confidence, explanation, action
taken (`COMMENTED` / `PROPOSED_NOT_EXPLOITABLE` / `SKIPPED_ALREADY_REVIEWED` /
`SKIPPED_COST_LIMIT` / `SKIPPED_CANCELLED` / `ERROR`), and how many data-flow nodes
had their source resolved (so path mismatches against `--repo-path` are visible).

### Run diagnostics (`logs/`)

Each run also writes a diagnostics directory `logs/<timestamp>_<scan-prefix>/`
(disable with `--log-dir off`):

- `run.jsonl` — every log record as JSON lines, always at debug level (no
  `--verbose` needed). Look for `"level":"WARN"` records like
  `sast result missing data` to spot findings the API returned without a query
  name or data-flow nodes.
- `checkmarx/` — raw response bodies of every Checkmarx API call, so you can
  check exactly what the API returned (e.g. whether `queryName`/`nodes` were
  present).
- `prompts/` and `responses/` — the full prompt sent to the AI per batch and the
  agent's raw output.

These files include source code snippets from the reviewed repo; `logs/` is
gitignored.

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
internal/ai                Reviewer interface + CLI-agent (claude/copilot) and Anthropic API implementations
internal/vcs               Bitbucket URL normalization + shallow clone
internal/logging           per-run diagnostics (JSONL log + raw artifact dumps)
internal/review            the orchestration pipeline
internal/report            JSON report model + writer
```

## Notes & assumptions

- **Checkmarx auth** uses the standard `ast-app` public client with the refresh-token
  grant. If your tenant uses an OAuth client id/secret instead, the token exchange in
  `internal/checkmarx/client.go` needs adjusting.
- **Agent auth** is out of scope for this tool: the `claude` / `copilot` CLI must
  already be installed and logged in, and the `anthropic` agent expects
  `ANTHROPIC_API_KEY` (or another standard SDK credential source) to already be set.
- **Agent invocation**:
  - `claude` (`internal/ai/cli.go`) is run as `claude -p --output-format json
    [--model M]` with the prompt on stdin; the JSON envelope's `result` field is
    unwrapped.
  - `copilot` (`internal/ai/cli.go`) is run as `copilot [--model M] --allow-all-tools
    -p "<prompt>"`.
  - `anthropic` (`internal/ai/api.go`) calls the Anthropic API directly via the Go
    SDK — no subprocess. With `--agentic-source` it runs an agentic tool-use loop
    (bounded iterations) granting the model read-only `Read`/`Grep`/`Glob`/`LS` tools
    sandboxed to `--repo-path`.
  - Every agent is asked to return a JSON **array** of verdict objects (one per
    finding in the batch, keyed by `id`); the parser tolerates surrounding prose or
    code fences, drops malformed/invalid verdicts, and the orchestrator re-reviews
    any dropped finding individually before recording it as `ERROR`. Adjust the
    `agentSpecs` table in `internal/ai/cli.go` if a CLI's flags change, or point
    `--agent-bin` at a wrapper.
- **Source paths**: node `fileName` values are treated as repo-root-relative to the
  resolved repo root (`--repo-path`, or the temp dir a Bitbucket URL was cloned
  into). Files that don't resolve are reported (not fatal) and the affected nodes
  are sent to the agent marked as unavailable.
- **Cost accounting** is per-agent: the `claude` CLI reports its own cost in its JSON
  envelope; the `anthropic` agent computes cost from token usage; `copilot` reports
  no cost, so `--cost-limit` has no effect when using it.
- **Engine scope**: SAST only.
