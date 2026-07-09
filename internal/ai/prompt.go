package ai

import (
	"fmt"
	"strings"
)

const promptPreamble = `You are a senior application security engineer performing SAST triage.
You are given one or more Checkmarx SAST findings. Each finding has a query (vulnerability
type), a source-to-sink data-flow path, and the actual source code around each node.

For EACH finding, decide whether it is a TRUE_POSITIVE (a real, exploitable vulnerability
that should be fixed) or a FALSE_POSITIVE (not exploitable in practice — e.g. the tainted
data is sanitized, validated, constant, not attacker-controlled, or the sink is safe in
this context).

Reason strictly from the code shown, and judge each finding independently. Trace whether
attacker-controllable input actually reaches the sink without adequate neutralization. If
the provided code is insufficient to be sure, lower your confidence rather than guessing.`

// promptInstruction is templated with the exact number of findings expected.
const promptInstruction = `Respond with ONLY a single JSON array and nothing else — no prose, no markdown, no code fences.
Return exactly one object per finding (%d in total), each keyed by the finding's id:
[{"id": "<finding id>", "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE", "confidence": <number between 0 and 1>, "explanation": "<concise justification grounded in the shown code, 2-5 sentences>"}]
Include every id exactly once.`

// buildBatchPrompt renders a self-contained prompt covering all findings. The
// agent has no tools and no repo access — all evidence is inlined here. Within a
// finding, source snippets whose line range is already fully shown by an earlier
// node are referenced rather than reprinted, to save tokens.
func buildBatchPrompt(findings []Finding) string {
	var b strings.Builder

	b.WriteString(promptPreamble)
	fmt.Fprintf(&b, "\n\nThere are %d finding(s) to review.\n", len(findings))

	for _, f := range findings {
		writeFinding(&b, f)
	}

	b.WriteString("\n")
	fmt.Fprintf(&b, promptInstruction, len(findings))
	return b.String()
}

// rng is a shown line range within a file.
type rng struct{ start, end int }

func writeFinding(b *strings.Builder, f Finding) {
	fmt.Fprintf(b, "\n===== FINDING id=%s =====\n", f.ID)
	fmt.Fprintf(b, "Vulnerability: %s\n", f.QueryName)
	if f.Group != "" {
		fmt.Fprintf(b, "Category: %s\n", f.Group)
	}
	if f.Language != "" {
		fmt.Fprintf(b, "Language: %s\n", f.Language)
	}
	if f.Severity != "" {
		fmt.Fprintf(b, "Severity: %s\n", f.Severity)
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		fmt.Fprintf(b, "Checkmarx description: %s\n", d)
	}

	b.WriteString("\nData-flow path (source → sink):\n")
	shown := map[string][]rng{} // per-file ranges already printed in this finding
	for _, n := range f.Nodes {
		fmt.Fprintf(b, "\n[%d] %s:%d", n.Order, n.FileName, n.Line)
		if n.Name != "" {
			fmt.Fprintf(b, "  (element: %s", n.Name)
			if n.Method != "" {
				fmt.Fprintf(b, " in %s", n.Method)
			}
			b.WriteString(")")
		}
		b.WriteString("\n")

		if !n.Resolved {
			fmt.Fprintf(b, "    [source unavailable: %s]\n", n.Snippet)
			continue
		}
		if covered(shown[n.FileName], n.StartLine, n.EndLine) {
			b.WriteString("    [code shown above for this file]\n")
			continue
		}
		b.WriteString(n.Snippet)
		b.WriteString("\n")
		shown[n.FileName] = append(shown[n.FileName], rng{n.StartLine, n.EndLine})
	}
	b.WriteString("\n===== END FINDING =====\n")
}

// covered reports whether [start,end] is fully contained in one already-shown range.
func covered(ranges []rng, start, end int) bool {
	if start == 0 && end == 0 {
		return false // no range info; never treat as covered
	}
	for _, r := range ranges {
		if start >= r.start && end <= r.end {
			return true
		}
	}
	return false
}
