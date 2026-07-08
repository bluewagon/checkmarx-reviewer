package ai

import (
	"fmt"
	"strings"
)

const systemPrompt = `You are a senior application security engineer performing SAST triage.
You are given a single Checkmarx SAST finding: its query (vulnerability type), the
source-to-sink data-flow path, and the actual source code around each node.

Decide whether the finding is a TRUE_POSITIVE (a real, exploitable vulnerability that
should be fixed) or a FALSE_POSITIVE (not exploitable in practice — e.g. the tainted
data is sanitized, validated, constant, not attacker-controlled, or the sink is safe in
this context).

Reason strictly from the code shown. Trace whether attacker-controllable input actually
reaches the sink without adequate neutralization. If the provided code is insufficient
to be sure, lower your confidence rather than guessing.

Return your judgment ONLY by calling the submit_verdict tool.`

// buildUserPrompt renders the finding into the user message text.
func buildUserPrompt(f Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Vulnerability: %s\n", f.QueryName)
	if f.Group != "" {
		fmt.Fprintf(&b, "Category: %s\n", f.Group)
	}
	if f.Language != "" {
		fmt.Fprintf(&b, "Language: %s\n", f.Language)
	}
	if f.Severity != "" {
		fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		fmt.Fprintf(&b, "Checkmarx description: %s\n", d)
	}

	b.WriteString("\nData-flow path (source → sink):\n")
	for _, n := range f.Nodes {
		fmt.Fprintf(&b, "\n[%d] %s:%d", n.Order, n.FileName, n.Line)
		if n.Name != "" {
			fmt.Fprintf(&b, "  (element: %s", n.Name)
			if n.Method != "" {
				fmt.Fprintf(&b, " in %s", n.Method)
			}
			b.WriteString(")")
		}
		b.WriteString("\n")
		if n.Resolved {
			b.WriteString(n.Snippet)
			b.WriteString("\n")
		} else {
			fmt.Fprintf(&b, "    [source unavailable: %s]\n", n.Snippet)
		}
	}

	b.WriteString("\nDecide TRUE_POSITIVE vs FALSE_POSITIVE and call submit_verdict.")
	return b.String()
}
