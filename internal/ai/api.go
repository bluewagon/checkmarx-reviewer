package ai

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/toolrunner"
)

// Defaults for the Anthropic API reviewer.
const (
	apiDefaultModel = "claude-opus-4-8"
	apiMaxTokens    = 16000
	// apiMaxIterations bounds the agentic tool-use loop per batch.
	apiMaxIterations = 25
)

// Caps on the read-only repo tools, so a single tool call cannot flood the
// context window.
const (
	toolReadMaxLines   = 2000
	toolGrepMaxMatches = 200
	toolGlobMaxEntries = 500
	toolGrepMaxFileMB  = 2
)

// APIReviewer implements Reviewer by calling the Anthropic API directly instead
// of driving an agent CLI. In agentic mode it runs a tool-use loop granting the
// model read-only repo tools (Read, Grep, Glob, LS) sandboxed to workDir.
// Authentication uses the SDK's standard resolution (ANTHROPIC_API_KEY etc.).
type APIReviewer struct {
	client  anthropic.Client
	model   string
	timeout time.Duration
	agentic bool
	workDir string
	log     *slog.Logger
}

// NewAPIReviewer builds an Anthropic API reviewer. model may be empty for the
// default. opts are extra SDK request options (used by tests to point the
// client at a fake server).
func NewAPIReviewer(model string, timeout time.Duration, agentic bool, workDir string, logger *slog.Logger, opts ...option.RequestOption) (*APIReviewer, error) {
	if model == "" {
		model = apiDefaultModel
	}
	if timeout <= 0 {
		timeout = DefaultAgentTimeout
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &APIReviewer{
		client:  anthropic.NewClient(opts...),
		model:   model,
		timeout: timeout,
		agentic: agentic,
		workDir: workDir,
		log:     logger,
	}, nil
}

// Model returns the effective model id.
func (r *APIReviewer) Model() string { return r.model }

// Agent returns the agent identifier.
func (r *APIReviewer) Agent() string { return AgentAnthropic }

// Review runs one batch of findings through the API and returns the parsed,
// normalized verdicts keyed by Finding.ID.
func (r *APIReviewer) Review(ctx context.Context, findings []Finding) (map[string]Verdict, Usage, error) {
	if len(findings) == 0 {
		return map[string]Verdict{}, Usage{}, nil
	}

	prompt := buildBatchPrompt(findings, r.agentic)

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ids := findingIDs(findings)
	r.log.Debug("agent invocation", "agent", AgentAnthropic, "model", r.model,
		"batchSize", len(findings), "agentic", r.agentic, "workDir", r.workDir)

	var text string
	var usage Usage
	var err error
	if r.agentic {
		text, usage, err = r.reviewAgentic(ctx, prompt)
	} else {
		text, usage, err = r.reviewOnce(ctx, prompt)
	}
	if err != nil {
		if apierr, ok := errors.AsType[*anthropic.Error](err); ok {
			r.log.Error("anthropic api call failed", "ids", ids,
				"status", apierr.StatusCode, "err", err)
		} else {
			r.log.Error("anthropic api call failed", "ids", ids, "err", err)
		}
		return nil, usage, fmt.Errorf("anthropic api call failed: %w", err)
	}

	verdicts, err := extractVerdicts(text)
	if err != nil {
		r.log.Error("agent output not parseable", "agent", AgentAnthropic, "ids", ids,
			"outputLen", len(text), "output", strings.TrimSpace(text))
		return nil, usage, fmt.Errorf("%s: %w; output was: %s", AgentAnthropic, err, truncate(text, 500))
	}
	return mapVerdicts(findings, verdicts), usage, nil
}

// reviewOnce performs a single non-agentic Messages call.
func (r *APIReviewer) reviewOnce(ctx context.Context, prompt string) (string, Usage, error) {
	adaptive := anthropic.ThinkingConfigAdaptiveParam{}
	resp, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(r.model),
		MaxTokens: apiMaxTokens,
		Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &adaptive},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return "", Usage{}, err
	}

	var b strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	usage := r.usageFrom(resp.Usage.InputTokens, resp.Usage.OutputTokens,
		resp.Usage.CacheCreationInputTokens, resp.Usage.CacheReadInputTokens)
	return b.String(), usage, nil
}

// reviewAgentic runs the beta tool-use loop with read-only repo tools, letting
// the model explore the checkout before answering. Usage is accumulated across
// every iteration of the loop.
func (r *APIReviewer) reviewAgentic(ctx context.Context, prompt string) (string, Usage, error) {
	tools, err := repoTools(r.workDir)
	if err != nil {
		return "", Usage{}, fmt.Errorf("building repo tools: %w", err)
	}

	adaptive := anthropic.BetaThinkingConfigAdaptiveParam{}
	runner := r.client.Beta.Messages.NewToolRunner(tools, anthropic.BetaToolRunnerParams{
		BetaMessageNewParams: anthropic.BetaMessageNewParams{
			Model:     anthropic.Model(r.model),
			MaxTokens: apiMaxTokens,
			Thinking:  anthropic.BetaThinkingConfigParamUnion{OfAdaptive: &adaptive},
			Messages: []anthropic.BetaMessageParam{
				anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt)),
			},
		},
		MaxIterations: apiMaxIterations,
	})

	var usage Usage
	var last *anthropic.BetaMessage
	iterations := 0
	for message, err := range runner.All(ctx) {
		if err != nil {
			return "", usage, err
		}
		if message == last {
			continue // the runner re-yields the final message on completion
		}
		iterations++
		usage.Add(r.usageFrom(message.Usage.InputTokens, message.Usage.OutputTokens,
			message.Usage.CacheCreationInputTokens, message.Usage.CacheReadInputTokens))
		last = message
	}
	if last == nil {
		return "", usage, fmt.Errorf("tool runner returned no message")
	}
	r.log.Debug("agentic loop finished", "iterations", iterations,
		"stopReason", string(last.StopReason))

	var b strings.Builder
	for _, block := range last.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String(), usage, nil
}

// usageFrom converts raw token counts into Usage with the cost computed from
// the model's pricing (zero cost for unknown models; tokens still tracked).
func (r *APIReviewer) usageFrom(in, out, cacheWrite, cacheRead int64) Usage {
	return Usage{
		InputTokens:              int(in),
		OutputTokens:             int(out),
		CacheCreationInputTokens: int(cacheWrite),
		CacheReadInputTokens:     int(cacheRead),
		CostUSD:                  computeCost(r.model, in, out, cacheWrite, cacheRead),
	}
}

// modelPricing is the USD price per million tokens. Cache writes bill at 1.25x
// the input rate (5-minute TTL) and cache reads at 0.1x.
type modelPricing struct {
	inPerMTok  float64
	outPerMTok float64
}

// apiPricing maps model-id prefixes to pricing. Longest matching prefix wins;
// models not listed (including older Opus generations with different pricing)
// compute zero cost, so the cost limit is simply not enforced for them.
var apiPricing = map[string]modelPricing{
	"claude-opus-4-8":   {5, 25},
	"claude-opus-4-7":   {5, 25},
	"claude-opus-4-6":   {5, 25},
	"claude-fable-5":    {10, 50},
	"claude-sonnet-5":   {3, 15},
	"claude-sonnet-4-6": {3, 15},
	"claude-haiku-4-5":  {1, 5},
}

// computeCost prices one API call's token usage in USD.
func computeCost(model string, in, out, cacheWrite, cacheRead int64) float64 {
	var best string
	for prefix := range apiPricing {
		if strings.HasPrefix(model, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return 0
	}
	p := apiPricing[best]
	return (float64(in)*p.inPerMTok +
		float64(out)*p.outPerMTok +
		float64(cacheWrite)*p.inPerMTok*1.25 +
		float64(cacheRead)*p.inPerMTok*0.1) / 1e6
}

// --- read-only repo tools for agentic mode ---

// toolText wraps a string as a tool-result content union. Tool failures are
// returned as text (never as a Go error) so the model can recover instead of
// aborting the whole loop.
func toolText(s string) anthropic.BetaToolResultBlockParamContentUnion {
	return anthropic.BetaToolResultBlockParamContentUnion{
		OfText: &anthropic.BetaTextBlockParam{Text: s},
	}
}

type readInput struct {
	Path   string `json:"path" jsonschema:"required,description=Repo-relative path of the file to read"`
	Offset int    `json:"offset,omitempty" jsonschema:"description=1-based line number to start reading from (default 1)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"description=Maximum number of lines to return (default 2000)"`
}

type grepInput struct {
	Pattern string `json:"pattern" jsonschema:"required,description=Regular expression (Go/RE2 syntax) to search for"`
	Path    string `json:"path,omitempty" jsonschema:"description=Repo-relative file or directory to search (default: whole repo)"`
}

type globInput struct {
	Pattern string `json:"pattern" jsonschema:"required,description=Glob pattern matched against repo-relative paths; * matches within a path segment and ** matches across segments (e.g. **/*.jsp)"`
}

type lsInput struct {
	Path string `json:"path,omitempty" jsonschema:"description=Repo-relative directory to list (default: repo root)"`
}

// repoTools builds the read-only tool set sandboxed to root.
func repoTools(root string) ([]anthropic.BetaTool, error) {
	read, err := toolrunner.NewBetaToolFromJSONSchema(
		"Read", "Read a file from the repository, returning numbered lines.",
		func(_ context.Context, in readInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			return toolText(toolRead(root, in)), nil
		})
	if err != nil {
		return nil, err
	}
	grep, err := toolrunner.NewBetaToolFromJSONSchema(
		"Grep", "Search file contents in the repository with a regular expression.",
		func(_ context.Context, in grepInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			return toolText(toolGrep(root, in)), nil
		})
	if err != nil {
		return nil, err
	}
	glob, err := toolrunner.NewBetaToolFromJSONSchema(
		"Glob", "Find files in the repository whose path matches a glob pattern.",
		func(_ context.Context, in globInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			return toolText(toolGlob(root, in)), nil
		})
	if err != nil {
		return nil, err
	}
	ls, err := toolrunner.NewBetaToolFromJSONSchema(
		"LS", "List the entries of a repository directory.",
		func(_ context.Context, in lsInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			return toolText(toolLS(root, in)), nil
		})
	if err != nil {
		return nil, err
	}
	return []anthropic.BetaTool{read, grep, glob, ls}, nil
}

// confine resolves rel inside root, rejecting any path that escapes it.
func confine(root, rel string) (string, error) {
	rel = strings.TrimLeft(filepath.FromSlash(rel), string(filepath.Separator))
	full := filepath.Join(root, rel)
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(rootAbs, fullAbs)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q resolves outside the repository root", rel)
	}
	return fullAbs, nil
}

func toolRead(root string, in readInput) string {
	full, err := confine(root, in.Path)
	if err != nil {
		return "error: " + err.Error()
	}
	f, err := os.Open(full)
	if err != nil {
		return fmt.Sprintf("error: cannot open %s: %v", in.Path, err)
	}
	defer f.Close()

	start := max(in.Offset, 1)
	limit := in.Limit
	if limit <= 0 || limit > toolReadMaxLines {
		limit = toolReadMaxLines
	}

	var b strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n, written := 0, 0
	for scanner.Scan() {
		n++
		if n < start {
			continue
		}
		if written >= limit {
			fmt.Fprintf(&b, "... truncated at %d lines; call Read again with offset=%d for more\n", limit, n)
			break
		}
		fmt.Fprintf(&b, "%6d| %s\n", n, scanner.Text())
		written++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Sprintf("error: reading %s: %v", in.Path, err)
	}
	if written == 0 {
		return fmt.Sprintf("(no lines: file has %d lines, offset was %d)", n, start)
	}
	return b.String()
}

func toolGrep(root string, in grepInput) string {
	re, err := regexp.Compile(in.Pattern)
	if err != nil {
		return "error: invalid pattern: " + err.Error()
	}
	base, err := confine(root, in.Path)
	if err != nil {
		return "error: " + err.Error()
	}

	var b strings.Builder
	matches := 0
	walkErr := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > toolGrepMaxFileMB*1024*1024 {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if re.MatchString(scanner.Text()) {
				fmt.Fprintf(&b, "%s:%d: %s\n", filepath.ToSlash(rel), line, scanner.Text())
				matches++
				if matches >= toolGrepMaxMatches {
					fmt.Fprintf(&b, "... truncated at %d matches; narrow the pattern or path\n", toolGrepMaxMatches)
					return filepath.SkipAll
				}
			}
		}
		_ = scanner.Err() // per-file scan error (e.g. oversize line): skip file
		return nil
	})
	if walkErr != nil {
		return "error: " + walkErr.Error()
	}
	if matches == 0 {
		return "no matches"
	}
	return b.String()
}

func toolGlob(root string, in globInput) string {
	pattern := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(in.Pattern)), "/")
	var b strings.Builder
	count := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if matchGlob(pattern, filepath.ToSlash(rel)) {
			b.WriteString(filepath.ToSlash(rel))
			b.WriteString("\n")
			count++
			if count >= toolGlobMaxEntries {
				fmt.Fprintf(&b, "... truncated at %d entries; narrow the pattern\n", toolGlobMaxEntries)
				return filepath.SkipAll
			}
		}
		return nil
	})
	if count == 0 {
		return "no files match"
	}
	return b.String()
}

// matchGlob matches a slash-separated relative path against a glob pattern
// where * matches within one segment and ** matches any number of segments.
func matchGlob(pattern, rel string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegs(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		// ** consumes zero or more segments.
		for i := 0; i <= len(segs); i++ {
			if matchSegs(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
		return false
	}
	return matchSegs(pat[1:], segs[1:])
}

func toolLS(root string, in lsInput) string {
	dir, err := confine(root, in.Path)
	if err != nil {
		return "error: " + err.Error()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Sprintf("error: cannot list %s: %v", in.Path, err)
	}
	if len(entries) == 0 {
		return "(empty directory)"
	}
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		b.WriteString(name)
		b.WriteString("\n")
	}
	return b.String()
}
