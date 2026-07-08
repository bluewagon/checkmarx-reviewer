package ai

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	maxTokens   = 1500
	verdictTool = "submit_verdict"
)

// AnthropicReviewer implements Reviewer using the Claude Messages API with a
// forced tool call so the verdict is returned as structured JSON.
type AnthropicReviewer struct {
	client anthropic.Client
	model  anthropic.Model
}

// NewAnthropicReviewer creates a reviewer using the given API key and model ID.
func NewAnthropicReviewer(apiKey, model string) *AnthropicReviewer {
	return &AnthropicReviewer{
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  anthropic.Model(model),
	}
}

func verdictToolParam() anthropic.ToolUnionParam {
	tool := anthropic.ToolParam{
		Name:        verdictTool,
		Description: anthropic.String("Submit the triage verdict for the SAST finding."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"verdict": map[string]any{
					"type":        "string",
					"enum":        []string{VerdictTruePositive, VerdictFalsePositive},
					"description": "TRUE_POSITIVE if the finding is a real exploitable vulnerability, FALSE_POSITIVE if it is not exploitable.",
				},
				"confidence": map[string]any{
					"type":        "number",
					"minimum":     0,
					"maximum":     1,
					"description": "Confidence in the verdict, from 0.0 to 1.0.",
				},
				"explanation": map[string]any{
					"type":        "string",
					"description": "Concise justification grounded in the shown code (2-5 sentences).",
				},
			},
			Required: []string{"verdict", "confidence", "explanation"},
		},
	}
	return anthropic.ToolUnionParam{OfTool: &tool}
}

// Review sends the finding to Claude and returns the parsed verdict.
func (r *AnthropicReviewer) Review(ctx context.Context, f Finding) (Verdict, error) {
	msg, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     r.model,
		MaxTokens: maxTokens,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildUserPrompt(f))),
		},
		Tools: []anthropic.ToolUnionParam{verdictToolParam()},
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfTool: &anthropic.ToolChoiceToolParam{Name: verdictTool},
		},
	})
	if err != nil {
		return Verdict{}, fmt.Errorf("anthropic request failed: %w", err)
	}

	for _, block := range msg.Content {
		if tu, ok := block.AsAny().(anthropic.ToolUseBlock); ok && tu.Name == verdictTool {
			var v Verdict
			if err := json.Unmarshal([]byte(tu.Input), &v); err != nil {
				return Verdict{}, fmt.Errorf("parsing verdict tool input: %w", err)
			}
			return normalize(v)
		}
	}
	return Verdict{}, fmt.Errorf("model did not return a %s tool call", verdictTool)
}

// normalize validates and clamps the model's verdict.
func normalize(v Verdict) (Verdict, error) {
	switch v.Verdict {
	case VerdictTruePositive, VerdictFalsePositive:
	default:
		return Verdict{}, fmt.Errorf("model returned invalid verdict %q", v.Verdict)
	}
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v, nil
}
