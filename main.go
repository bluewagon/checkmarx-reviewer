// Command checkmarx-reviewer reviews To-Verify SAST findings from a single
// Checkmarx One scan (HIGH severity by default; see --severity) with an AI
// model, posting a true/false-positive verdict as a comment on each finding and
// proposing "Not Exploitable" for high-confidence false positives.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bluewagon/checkmarx-reviewer/internal/ai"
	"github.com/bluewagon/checkmarx-reviewer/internal/checkmarx"
	"github.com/bluewagon/checkmarx-reviewer/internal/config"
	"github.com/bluewagon/checkmarx-reviewer/internal/logging"
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
	if len(args) > 0 && args[0] == "resume" {
		return runResume(args[1:])
	}

	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	logger, runLog, err := logging.NewRun(cfg.LogDir, cfg.ScanID, cfg.Verbose)
	if err != nil {
		return fmt.Errorf("setting up logging: %w", err)
	}
	defer runLog.Close()
	if runLog != nil {
		logger.Info("file logging enabled", "dir", runLog.Dir())
	}
	logger.Info("run configuration", "scanId", cfg.ScanID, "severities", cfg.Severities, "agent", cfg.Agent,
		"model", cfg.Model, "batchSize", cfg.BatchSize, "concurrency", cfg.Concurrency,
		"agenticSource", cfg.AgenticSource, "reTriage", cfg.ReTriage, "limit", cfg.Limit, "dryRun", cfg.DryRun,
		"stripPathPrefix", cfg.StripPathPrefix)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cx := checkmarx.New(checkmarx.Options{
		BaseURI: cfg.BaseURI,
		Tenant:  cfg.Tenant,
		APIKey:  cfg.APIKey,
		Logger:  logger,
		Dump:    runLog.Dump,
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

	reviewer, err := ai.NewReviewer(cfg.Agent, cfg.Model, cfg.AgentBin, cfg.AgentTimeout, cfg.AgenticSource, repoRoot, logger, runLog.Dump)
	if err != nil {
		return err
	}
	if cfg.AgenticSource {
		logger.Info("agentic source access enabled", "repo", repoRoot)
	}
	reader := source.NewReader(repoRoot, cfg.ContextLines)

	orch := review.New(cx, reviewer, reader, review.Options{
		ScanID:          cfg.ScanID,
		Severities:      cfg.Severities,
		StripPathPrefix: cfg.StripPathPrefix,
		Agent:           cfg.Agent,
		Model:           reviewer.Model(),
		BatchSize:       cfg.BatchSize,
		Concurrency:     cfg.Concurrency,
		FPThreshold:     cfg.FPThreshold,
		CostLimitUSD:    cfg.CostLimitUSD,
		ReTriage:        cfg.ReTriage,
		Limit:           cfg.Limit,
		DryRun:          cfg.DryRun,
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

	// On a limited run, list the findings that were reviewed (by similarityID) so
	// they are easy to locate in Checkmarx.
	if cfg.Limit > 0 {
		for _, f := range rep.Findings {
			if report.IsReviewed(f.Action) {
				logger.Info("reviewed finding", "query", f.QueryName, "severity", f.Severity,
					"verdict", f.Verdict, "similarityId", f.SimilarityID)
			}
		}
	}

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

// runResume re-posts predicates for findings that were verdicted but never posted
// (post failures, or a run cancelled mid-posting), reading them from an existing
// report and rebuilding each comment/state — no AI calls or scan listing.
func runResume(args []string) error {
	cfg, err := config.LoadResume(args)
	if err != nil {
		return err
	}

	rep, err := report.ReadJSON(cfg.ReportIn)
	if err != nil {
		return fmt.Errorf("reading report %q: %w", cfg.ReportIn, err)
	}

	logger, runLog, err := logging.NewRun(cfg.LogDir, rep.ScanID, cfg.Verbose)
	if err != nil {
		return fmt.Errorf("setting up logging: %w", err)
	}
	defer runLog.Close()
	if runLog != nil {
		logger.Info("file logging enabled", "dir", runLog.Dir())
	}
	logger.Info("resume configuration", "report", cfg.ReportIn, "reportOut", cfg.ReportOut,
		"scanId", rep.ScanID, "projectId", rep.ProjectID, "concurrency", cfg.Concurrency,
		"dryRun", cfg.DryRun)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cx := checkmarx.New(checkmarx.Options{
		BaseURI: cfg.BaseURI,
		Tenant:  cfg.Tenant,
		APIKey:  cfg.APIKey,
		Logger:  logger,
		Dump:    runLog.Dump,
	})

	if cfg.DryRun {
		logger.Info("dry run: no comments or state changes will be written to Checkmarx")
	}

	summary := review.Resume(ctx, cx, rep, review.ResumeOptions{
		Concurrency: cfg.Concurrency,
		DryRun:      cfg.DryRun,
	}, logger)

	if !cfg.DryRun {
		if err := report.WriteJSON(cfg.ReportOut, rep); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	logger.Info("resume done", "candidates", summary.Candidates, "reposted", summary.Reposted,
		"failed", summary.Failed, "noVerdictSkipped", summary.NoVerdictSkipped,
		"report", cfg.ReportOut, "dryRun", cfg.DryRun)

	// Non-zero exit if any predicate still failed to post, so pipelines notice.
	if summary.Failed > 0 {
		return fmt.Errorf("%d predicate(s) still failed to post", summary.Failed)
	}
	return nil
}
