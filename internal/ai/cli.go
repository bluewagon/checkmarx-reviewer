package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Supported agent CLIs.
const (
	AgentClaude  = "claude"  // Claude Code CLI (`claude`)
	AgentCopilot = "copilot" // GitHub Copilot CLI (`copilot`)
)

// DefaultAgentTimeout bounds a single agent invocation.
const DefaultAgentTimeout = 180 * time.Second

// agentSpec describes how to drive one CLI agent in non-interactive mode.
type agentSpec struct {
	bin            string
	defaultModel   string
	promptViaStdin bool // pass the prompt on stdin vs. as the final arg
	// args builds the CLI args for the given model. When agentic is true the agent
	// is granted read-only repo tools (it runs with the repo as its working dir).
	args func(model string, agentic bool) []string
	// extract pulls the assistant text and any reported token/cost usage out of
	// stdout. Agents that report no usage return a zero Usage.
	extract func(stdout []byte) (string, Usage)
}

var agentSpecs = map[string]agentSpec{
	// claude -p --output-format json [--model M]   (prompt on stdin)
	AgentClaude: {
		bin:            "claude",
		defaultModel:   "claude-opus-4-8",
		promptViaStdin: true,
		args: func(model string, agentic bool) []string {
			a := []string{"-p", "--output-format", "json"}
			if model != "" {
				a = append(a, "--model", model)
			}
			if agentic {
				// Read-only exploration of the repo checked out at the working dir.
				a = append(a, "--allowedTools", "Read Grep Glob LS")
			}
			return a
		},
		extract: extractClaudeResult,
	},
	// copilot [--model M] (--deny-tool … | --allow-all-tools --allow-all-paths) -p "<prompt>"
	AgentCopilot: {
		bin:            "copilot",
		defaultModel:   "", // let Copilot use its configured default
		promptViaStdin: false,
		args: func(model string, agentic bool) []string {
			var a []string
			if model != "" {
				a = append(a, "--model", model)
			}
			if agentic {
				// Grant tools AND path trust so it can read the repo checked out at
				// its working directory (Copilot gates tools and paths separately).
				a = append(a, "--allow-all-tools", "--allow-all-paths")
			} else {
				// No repo access: deny the read/search/mutation tools so Copilot
				// reasons purely from the inlined snippets instead of attempting
				// (and failing) file searches. Deny always wins in Copilot.
				a = append(a, "--deny-tool", copilotNonAgenticDenyTools)
			}
			return append(a, "-p")
		},
		extract: func(b []byte) (string, Usage) { return string(b), Usage{} },
	},
}

// copilotNonAgenticDenyTools is the comma-separated list of Copilot built-in tool
// kinds denied in non-agentic mode. Copilot has no single "deny-all" flag, so we
// enumerate the tools that would touch the filesystem, run commands, or reach the
// network; deny rules take precedence over any allow.
const copilotNonAgenticDenyTools = "shell,write,edit,read,view,grep,glob,web_fetch,web_search"

// SupportedAgents lists the agent identifiers accepted by NewCLIReviewer.
func SupportedAgents() []string { return []string{AgentClaude, AgentCopilot} }

// runner executes a command in dir (empty = inherit); abstracted so tests can
// inject a fake.
type runner func(ctx context.Context, bin string, args []string, stdin []byte, dir string) (stdout, stderr []byte, err error)

// CLIReviewer implements Reviewer by shelling out to an AI agent CLI. The agent
// is given a self-contained prompt and must reply with a JSON verdict. In agentic
// mode it also runs with workDir as its working directory and is granted
// read-only tools so it can explore the repo checkout for extra context.
type CLIReviewer struct {
	agent   string
	spec    agentSpec
	bin     string
	model   string
	timeout time.Duration
	agentic bool
	workDir string
	log     *slog.Logger
	run     runner
}

// NewCLIReviewer builds a reviewer for the named agent ("claude" or "copilot").
// model may be empty to use the agent's default. binOverride, when non-empty,
// replaces the default binary name. It verifies the binary is on PATH.
func NewCLIReviewer(agent, model, binOverride string, timeout time.Duration, agentic bool, workDir string, logger *slog.Logger) (*CLIReviewer, error) {
	spec, ok := agentSpecs[agent]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q (supported: %s)", agent, strings.Join(SupportedAgents(), ", "))
	}
	bin := spec.bin
	if binOverride != "" {
		bin = binOverride
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("agent CLI %q not found on PATH: %w", bin, err)
	}
	if model == "" {
		model = spec.defaultModel
	}
	if timeout <= 0 {
		timeout = DefaultAgentTimeout
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &CLIReviewer{agent: agent, spec: spec, bin: bin, model: model, timeout: timeout, agentic: agentic, workDir: workDir, log: logger, run: execRunner}, nil
}

// Model returns the effective model (may be empty for an agent default).
func (r *CLIReviewer) Model() string { return r.model }

// Agent returns the agent identifier.
func (r *CLIReviewer) Agent() string { return r.agent }

// Review runs the agent on a batch of findings in one invocation and returns the
// parsed, normalized verdicts keyed by Finding.ID. Verdicts that fail validation
// are dropped from the map (the caller re-reviews or records them as errors).
func (r *CLIReviewer) Review(ctx context.Context, findings []Finding) (map[string]Verdict, Usage, error) {
	if len(findings) == 0 {
		return map[string]Verdict{}, Usage{}, nil
	}

	prompt := buildBatchPrompt(findings, r.agentic)

	args := r.spec.args(r.model, r.agentic)
	var stdin []byte
	if r.spec.promptViaStdin {
		stdin = []byte(prompt)
	} else {
		args = append(args, prompt)
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// In agentic mode the agent reads the repo relative to its working directory.
	dir := ""
	if r.agentic {
		dir = r.workDir
	}
	ids := findingIDs(findings)
	r.log.Debug("agent invocation", "agent", r.agent, "model", r.model,
		"batchSize", len(findings), "workDir", dir, "args", strings.Join(args, " "))

	stdout, stderr, err := r.run(ctx, r.bin, args, stdin, dir)
	if err != nil {
		// Log the full stderr for diagnosis; keep the returned error short so it
		// stays readable in the report.
		r.log.Error("agent invocation failed", "agent", r.agent, "ids", ids,
			"err", err, "stderr", strings.TrimSpace(string(stderr)))
		return nil, Usage{}, fmt.Errorf("%s invocation failed: %w: %s", r.agent, err, truncate(string(stderr), 500))
	}

	text, usage := r.spec.extract(stdout)
	verdicts, err := extractVerdicts(text)
	if err != nil {
		r.log.Error("agent output not parseable", "agent", r.agent, "ids", ids,
			"outputLen", len(text), "output", strings.TrimSpace(text))
		return nil, usage, fmt.Errorf("%s: %w; output was: %s", r.agent, err, truncate(text, 500))
	}

	// Single-item robustness: if the agent omitted the id, backfill it.
	if len(findings) == 1 && len(verdicts) == 1 && verdicts[0].ID == "" {
		verdicts[0].ID = findings[0].ID
	}

	out := make(map[string]Verdict, len(verdicts))
	for _, v := range verdicts {
		if v.ID == "" {
			continue
		}
		nv, err := normalize(v)
		if err != nil {
			continue // invalid verdict: leave absent so the caller recovers
		}
		nv.ID = v.ID
		out[v.ID] = nv
	}
	return out, usage, nil
}

// execRunner is the production runner backed by os/exec. dir, when non-empty,
// sets the command's working directory.
func execRunner(ctx context.Context, bin string, args []string, stdin []byte, dir string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// extractClaudeResult unwraps Claude Code's `--output-format json` envelope to
// the assistant's text plus the token/cost usage it reports. Falls back to the
// raw bytes with zero usage if it isn't that envelope.
func extractClaudeResult(stdout []byte) (string, Usage) {
	var env struct {
		Result  string  `json:"result"`
		IsError bool    `json:"is_error"`
		CostUSD float64 `json:"total_cost_usd"`
		Usage   struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &env); err == nil && env.Result != "" {
		return env.Result, Usage{
			InputTokens:              env.Usage.InputTokens,
			OutputTokens:             env.Usage.OutputTokens,
			CacheCreationInputTokens: env.Usage.CacheCreationInputTokens,
			CacheReadInputTokens:     env.Usage.CacheReadInputTokens,
			CostUSD:                  env.CostUSD,
		}
	}
	return string(stdout), Usage{}
}

// extractVerdicts parses one or more Verdicts from agent output that may contain
// surrounding prose or code fences: it tries a top-level JSON array first, then
// falls back to collecting every balanced JSON object that carries a "verdict".
func extractVerdicts(text string) ([]Verdict, error) {
	if arr, ok := tryVerdictArray(text); ok {
		return arr, nil
	}
	var out []Verdict
	for _, obj := range jsonObjects(text) {
		if v, ok := tryVerdict(obj); ok {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no JSON verdict object found in agent output")
	}
	return out, nil
}

// tryVerdictArray attempts to unmarshal the first top-level [...] as []Verdict.
func tryVerdictArray(text string) ([]Verdict, bool) {
	raw, ok := firstJSONArray(text)
	if !ok {
		return nil, false
	}
	var arr []Verdict
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return nil, false
	}
	// Keep only objects that actually carry a verdict.
	var out []Verdict
	for _, v := range arr {
		if v.Verdict != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// tryVerdict reports whether s is a JSON object with a non-empty verdict field.
func tryVerdict(s string) (Verdict, bool) {
	var v Verdict
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return Verdict{}, false
	}
	if v.Verdict == "" {
		return Verdict{}, false
	}
	return v, true
}

// jsonObjects returns the top-level {...} substrings in s, honoring string
// literals and escapes so braces inside strings don't break balance tracking.
func jsonObjects(s string) []string {
	var objs []string
	depth := 0
	start := -1
	inStr := false
	escaped := false
	for i, r := range s {
		if inStr {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					objs = append(objs, s[start:i+1])
					start = -1
				}
			}
		}
	}
	return objs
}

// firstJSONArray returns the first top-level [...] substring in s, honoring
// string literals and escapes so brackets inside strings don't break balance.
func firstJSONArray(s string) (string, bool) {
	depth := 0
	start := -1
	inStr := false
	escaped := false
	for i, r := range s {
		if inStr {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case '[':
			if depth == 0 {
				start = i
			}
			depth++
		case ']':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					return s[start : i+1], true
				}
			}
		}
	}
	return "", false
}

// findingIDs collects the ids of a batch for log context.
func findingIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
