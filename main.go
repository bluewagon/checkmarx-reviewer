// Command checkmarx-reviewer reviews HIGH/To-Verify SAST findings from a single
// Checkmarx One scan with an AI model, posting a true/false-positive verdict as a
// comment on each finding and proposing "Not Exploitable" for high-confidence
// false positives.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/config"
	"github.com/bluewagon/checkmarx-reviewer/internal/report"
	"github.com/bluewagon/checkmarx-reviewer/internal/review"
	"github.com/bluewagon/checkmarx-reviewer/internal/source"
	"github.com/bluewagon/checkmarx-reviewer/internal/vcs"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cx := checkmarx.New(checkmarx.Options{
		BaseURI: cfg.BaseURI,
		Tenant:  cfg.Tenant,
		APIKey:  cfg.APIKey,
		Logger:  logger,
	})
	// Resolve the repo root first (cloning a Bitbucket URL if given) so the reviewer
	// can be pointed at it for agentic source access.
	repoRoot := cfg.RepoPath
	if vcs.IsRemoteURL(cfg.RepoPath) {
		cloneURL, err := vcs.NormalizeBitbucketURL(cfg.RepoPath)
		if err != nil {
			return err
		}
		logger.Info("cloning repo (shallow)", "url", cloneURL)
		dir, cleanup, err := vcs.CloneToTemp(ctx, cloneURL, cfg.BitbucketToken)
		if err != nil {
			logger.Error("clone failed", "url", cloneURL, "err", err)
			return fmt.Errorf("cloning repo: %w", err)
		}
		defer cleanup()
		repoRoot = dir
	}

	reviewer, err := ai.NewCLIReviewer(cfg.Agent, cfg.Model, cfg.AgentBin, cfg.AgentTimeout, cfg.AgenticSource, repoRoot, logger)
	if err != nil {
		return err
	}
	if cfg.AgenticSource {
		logger.Info("agentic source access enabled", "repo", repoRoot)
	}
	reader := source.NewReader(repoRoot, cfg.ContextLines)

	orch := review.New(cx, reviewer, reader, review.Options{
		ScanID:       cfg.ScanID,
		Agent:        cfg.Agent,
		Model:        reviewer.Model(),
		BatchSize:    cfg.BatchSize,
		Concurrency:  cfg.Concurrency,
		FPThreshold:  cfg.FPThreshold,
		CostLimitUSD: cfg.CostLimitUSD,
		DryRun:       cfg.DryRun,
	}, logger)

	if cfg.DryRun {
		logger.Info("dry run: no comments or state changes will be written to Checkmarx")
	}

	rep, err := orch.Run(ctx)
	if err != nil {
		return err
	}

	if err := report.WriteJSON(cfg.ReportPath, rep); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	logger.Info("done",
		"reviewed", rep.Reviewed, "skipped", rep.Skipped, "errors", rep.Errors,
		"truePositives", rep.TruePositives, "falsePositives", rep.FalsePositives,
		"stateChanges", rep.StateChanges,
		"costUsd", fmt.Sprintf("%.4f", rep.EstimatedCostUSD), "tokens", rep.TotalTokens,
		"report", cfg.ReportPath)

	// Non-zero exit if the run aborted on the cost limit, so pipelines notice the
	// review was incomplete.
	if rep.Aborted {
		return fmt.Errorf("run stopped early: %s", rep.AbortReason)
	}

	// Non-zero exit if any finding failed, so pipelines can detect problems.
	if rep.Errors > 0 {
		return fmt.Errorf("%d finding(s) failed during review", rep.Errors)
	}
	return nil
}
