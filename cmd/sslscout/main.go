// Command sslscout checks the TLS certificates of a list of domains, publishes
// a report.json for the dashboard and fires the alerts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"sslscout/pkg/checker"
	"sslscout/pkg/config"
	"sslscout/pkg/i18n"
	"sslscout/pkg/notifier"
	"sslscout/pkg/report"
)

// version is overwritten at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// Exit codes (useful in CI).
const (
	exitOK        = 0 // all good
	exitError     = 1 // execution error (config, file, write, server)
	exitThreshold = 2 // -fail-on was reached
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	domains     string
	config      string
	out         string
	timeout     time.Duration
	concurrency int
	retries     int
	threshold   int
	critical    int
	lang        string
	notify      bool
	serve       string
	interval    time.Duration
	failOn      string
	quiet       bool
	version     bool
}

func run(args []string, stdout, stderr io.Writer) int {
	defaults := config.Default()

	var o options
	fs := flag.NewFlagSet("sslscout", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.domains, "domains", "domains.txt", "domain list file")
	fs.StringVar(&o.config, "config", "config.json", "configuration file")
	fs.StringVar(&o.out, "out", filepath.Join("public", "report.json"), "path of the JSON report")
	fs.DurationVar(&o.timeout, "timeout", defaults.Timeout(), "per-connection timeout")
	fs.IntVar(&o.concurrency, "concurrency", defaults.Concurrency, "simultaneous checks")
	fs.IntVar(&o.retries, "retries", defaults.Retries, "attempts per domain on transient failures")
	fs.IntVar(&o.threshold, "threshold", defaults.AlertThresholdDays, "overrides alert_threshold_days")
	fs.IntVar(&o.critical, "critical", defaults.CriticalThresholdDays, "overrides critical_threshold_days")
	fs.StringVar(&o.lang, "lang", defaults.Language,
		"language of the notifications: "+strings.Join(i18n.SupportedNames(), "|")+" (the CLI output is always English)")
	fs.BoolVar(&o.notify, "notify", true, "send notifications (use -notify=false to turn them off)")
	fs.StringVar(&o.serve, "serve", "", "after checking, serve the report directory on this address (e.g. \":8080\")")
	fs.DurationVar(&o.interval, "interval", 0, "re-run the check on this interval (0 = run once)")
	fs.StringVar(&o.failOn, "fail-on", "none", "exit non-zero if any result is at this level or worse: none|warning|critical|invalid|error")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress informational output")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "sslscout [flags]\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: %d success, %d execution error, %d -fail-on threshold reached.\n",
			exitOK, exitError, exitThreshold)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if o.version {
		fmt.Fprintln(stdout, fullVersion())
		return exitOK
	}

	printf := func(format string, a ...any) {
		if !o.quiet {
			fmt.Fprintf(stdout, format+"\n", a...)
		}
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "sslscout: %v\n", err)
		return exitError
	}

	// Precedence: explicit flag > config file > built-in default.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg, found, err := config.Load(o.config)
	if err != nil {
		return fail(err)
	}
	if !found && set["config"] {
		return fail(fmt.Errorf("configuration file %s not found", o.config))
	}
	cfg.ApplyEnv(nil)
	applyFlags(&cfg, o, set)

	if err := cfg.Validate(); err != nil {
		return fail(fmt.Errorf("invalid configuration:\n%w", err))
	}

	severityThreshold, ok := checker.SeverityFromName(o.failOn)
	if !ok {
		return fail(fmt.Errorf("invalid -fail-on %q (use none|warning|critical|invalid|error)", o.failOn))
	}
	if o.interval < 0 {
		return fail(fmt.Errorf("-interval cannot be negative (%s)", o.interval))
	}

	targets, err := checker.LoadTargets(o.domains)
	if err != nil {
		return fail(err)
	}
	if len(targets) == 0 {
		return fail(fmt.Errorf("no valid domain in %s", o.domains))
	}

	// The bind happens before the first check so that "port already in use"
	// fails right away instead of after minutes of work.
	var listener net.Listener
	if o.serve != "" {
		listener, err = net.Listen("tcp", o.serve)
		if err != nil {
			return fail(fmt.Errorf("could not listen on %s: %w", o.serve, err))
		}
	}

	var servers sync.WaitGroup
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// LIFO: stop() cancels the context and only then do we wait for the server.
	defer servers.Wait()
	defer stop()

	serverError := make(chan error, 1)
	if listener != nil {
		dir := filepath.Dir(o.out)
		printf("Serving %s at http://%s/", dir, listener.Addr())
		servers.Add(1)
		go func() {
			defer servers.Done()
			serverError <- serve(ctx, listener, dir, filepath.Base(o.out))
		}()
	}

	var worst int
	for {
		rep, err := checkOnce(ctx, cfg, targets, o, printf, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "sslscout: %v\n", err)
			if o.interval <= 0 {
				return exitError
			}
		} else {
			worst = rep.WorstSeverity()
		}

		if o.interval <= 0 {
			break
		}
		printf("Next check in %s (Ctrl-C to quit).", o.interval)
		timer := time.NewTimer(o.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			printf("Shutting down…")
			return shutdownServer(serverError, listener, stderr)
		case err := <-serverError:
			timer.Stop()
			if err != nil {
				return fail(err)
			}
			return exitOK // the server exited cleanly: nothing left to do here
		case <-timer.C:
		}
	}

	// No -interval but -serve is on: stay up until the shutdown signal.
	if listener != nil {
		select {
		case <-ctx.Done():
			printf("Shutting down…")
		case err := <-serverError:
			if err != nil {
				return fail(err)
			}
		}
		return exitOK
	}

	if worst >= severityThreshold {
		fmt.Fprintf(stderr, "sslscout: -fail-on=%s threshold reached.\n", o.failOn)
		return exitThreshold
	}
	return exitOK
}

func shutdownServer(serverError chan error, listener net.Listener, stderr io.Writer) int {
	if listener == nil {
		return exitOK
	}
	select {
	case err := <-serverError:
		if err != nil {
			fmt.Fprintf(stderr, "sslscout: %v\n", err)
			return exitError
		}
	case <-time.After(10 * time.Second):
	}
	return exitOK
}

// applyFlags overrides the configuration only with the flags actually given.
func applyFlags(cfg *config.Config, o options, set map[string]bool) {
	if set["timeout"] {
		cfg.TimeoutOverride = o.timeout
	}
	if set["concurrency"] {
		cfg.Concurrency = o.concurrency
	}
	if set["retries"] {
		cfg.Retries = o.retries
	}
	if set["threshold"] {
		cfg.AlertThresholdDays = o.threshold
	}
	if set["critical"] {
		cfg.CriticalThresholdDays = o.critical
	}
	if set["lang"] {
		cfg.Language = o.lang
	}
}

// checkOnce runs one full cycle: check, report and notifications.
func checkOnce(ctx context.Context, cfg config.Config, targets []checker.Target, o options,
	printf func(string, ...any), stderr io.Writer) (*report.Report, error) {

	start := time.Now()
	printf("SSLScout — checking %d target(s) with concurrency %d…", len(targets), cfg.Concurrency)

	results := checkAll(ctx, cfg, targets)
	rep := report.Build(results, time.Now(), time.Since(start),
		cfg.AlertThresholdDays, cfg.CriticalThresholdDays)

	// Interrupted midway: the results are garbage (everything turns into
	// "context canceled"). Better to keep the previous report than ruin it.
	if ctx.Err() != nil {
		printf("Check interrupted; the previous report was preserved.")
		return rep, nil
	}

	if err := report.Write(o.out, rep); err != nil {
		return rep, err
	}

	if !o.quiet {
		for _, r := range rep.Results {
			printf("  %-9s %s%s", r.Status, r.Domain, detail(r))
		}
	}
	s := rep.Summary
	printf("Summary: total=%d ok=%d warning=%d critical=%d expired=%d invalid=%d error=%d (%s)",
		s.Total, s.OK, s.Warning, s.Critical, s.Expired, s.Invalid, s.Error,
		time.Duration(rep.DurationMS)*time.Millisecond)
	printf("Report written to %s", o.out)

	if o.notify {
		if err := notifier.Notify(cfg, rep.Results); err != nil {
			// A notification failure does not invalidate the check: report and move on.
			fmt.Fprintf(stderr, "sslscout: could not notify:\n%v\n", err)
		}
	}
	return rep, nil
}

// checkAll fires the checks while respecting the concurrency limit. The
// semaphore slot is acquired BEFORE spawning the goroutine: with a list of ten
// thousand domains there is no point in creating ten thousand goroutines just
// so they can wait.
func checkAll(ctx context.Context, cfg config.Config, targets []checker.Target) []checker.Result {
	opts := checker.Options{
		Timeout:               cfg.Timeout(),
		Retries:               cfg.Retries,
		AlertThresholdDays:    cfg.AlertThresholdDays,
		CriticalThresholdDays: cfg.CriticalThresholdDays,
	}

	results := make([]checker.Result, len(targets))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	started := 0
	for i, target := range targets {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return results[:started]
		}
		started++
		wg.Add(1)
		go func(i int, target checker.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = checker.Check(ctx, target.String(), opts)
		}(i, target)
	}
	wg.Wait()
	return results
}

func detail(r checker.Result) string {
	switch {
	case r.Status == checker.StatusError:
		return fmt.Sprintf(" — %s: %s", r.ErrorKind, r.Error)
	case r.ExpiresAt != nil:
		return fmt.Sprintf(" — %d day(s), expires on %s", r.DaysRemaining, r.ExpiresAt.Format("2006-01-02"))
	default:
		return ""
	}
}

// serve publishes the report directory. report.json goes out with no-store so
// the dashboard never shows stale cached data.
func serve(ctx context.Context, listener net.Listener, dir, reportFile string) error {
	srv := &http.Server{
		Handler:           noCache(http.FileServer(http.Dir(dir)), reportFile),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server: %w", err)
	}
	return nil
}

func noCache(h http.Handler, reportFile string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Base(r.URL.Path) == reportFile {
			w.Header().Set("Cache-Control", "no-store, max-age=0")
		} else {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		}
		h.ServeHTTP(w, r)
	})
}

func fullVersion() string {
	v := version
	revision := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) > 12 {
					revision = s.Value[:12]
				} else {
					revision = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" && revision != "" {
					revision += "+dirty"
				}
			}
		}
	}
	if revision != "" {
		return fmt.Sprintf("sslscout %s (%s, %s)", v, revision, runtime.Version())
	}
	return fmt.Sprintf("sslscout %s (%s)", v, runtime.Version())
}
