package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/taotecode/bercert/internal/config"
	"github.com/taotecode/bercert/internal/engine"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage()
	}
	if cmd == "-version" || cmd == "--version" || cmd == "version" {
		fmt.Println("bercert", version)
		return
	}
	if cmd != "scan" && cmd != "renew" && cmd != "daemon" && cmd != "doctor" && cmd != "schedule" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	envFile := fs.String("env", ".env", "path to env file")
	renewBefore := fs.String("renew-before", "", "renew when certificate expires within this window (e.g. 30d, 720h)")
	provider := fs.String("provider", "all", "qiniu, upyun or all")
	domainFilter := fs.String("domain", "", "comma-separated domains to operate on")
	jsonOut := fs.Bool("json", false, "print JSON instead of a table")
	dryRun := fs.Bool("dry-run", false, "show what would change without changing anything")
	force := fs.Bool("force", false, "renew even when the current certificate is healthy")
	allowUncovered := fs.Bool("allow-uncovered", false, "exit 0 when no 1Panel certificate covers a domain")
	issue := fs.Bool("issue", false, "request missing certificates from 1Panel")
	noIssue := fs.Bool("no-issue", false, "never request certificates from 1Panel")
	retryUntilSuccess := fs.Bool("retry-until-success", false, "keep retrying a failed 1Panel issuance until it succeeds")
	at := fs.String("at", "04:17", "schedule: daily run time in the server's local timezone (HH:MM)")
	runNow := fs.Bool("run-now", true, "schedule: run once at startup before waiting")
	failureRetry := fs.Duration("failure-retry", 10*time.Minute, "schedule: retry after this delay when a run has failures (0 disables)")
	interval := fs.Duration("interval", 6*time.Hour, "daemon scan interval")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*envFile)
	if err != nil {
		fatal(err)
	}
	if *renewBefore != "" {
		d, err := parseWindow(*renewBefore)
		if err != nil {
			fatal(err)
		}
		cfg.RenewBefore = d
	}
	if *issue {
		cfg.PanelIssueEnabled = true
	}
	if *noIssue {
		cfg.PanelIssueEnabled = false
	}
	if *retryUntilSuccess {
		cfg.PanelIssueRetries = 0
	}

	eng := engine.New(cfg)
	eng.Logf = log.Printf
	if *provider == "qiniu" {
		eng.Upyun = nil
	}
	if *provider == "upyun" {
		eng.Qiniu = nil
	}
	if *provider != "all" && *provider != "qiniu" && *provider != "upyun" {
		fatal(fmt.Errorf("--provider must be qiniu, upyun or all"))
	}

	switch cmd {
	case "doctor":
		runDoctor(eng)
	case "scan":
		actions, err := eng.Scan(context.Background())
		if err != nil {
			fatal(err)
		}
		actions = filterActions(actions, *domainFilter)
		printActions(actions, *jsonOut)
		if needsAttention(actions) {
			os.Exit(1)
		}
	case "renew":
		ctx := context.Background()
		actions, err := eng.Scan(ctx)
		if err != nil {
			fatal(err)
		}
		actions = filterActions(actions, *domainFilter)
		actions, err = eng.Apply(ctx, actions, *dryRun, *force)
		if err != nil {
			fatal(err)
		}
		printActions(actions, *jsonOut)
		if failed(actions, !*allowUncovered) || (mustApply(actions) && *dryRun) {
			os.Exit(1)
		}
	case "daemon":
		runDaemon(eng, *interval, *domainFilter, *jsonOut, *force)
	case "schedule":
		if _, _, err := parseDailyAt(*at); err != nil {
			fatal(err)
		}
		runSchedule(eng, *at, *runNow, *failureRetry, *domainFilter, *jsonOut, *force)
	}
}

func runCycle(ctx context.Context, eng *engine.Engine, domainFilter string, jsonOut, force bool) bool {
	actions, err := eng.Scan(ctx)
	if err != nil {
		log.Printf("scan failed: %v", err)
		return false
	}
	actions = filterActions(actions, domainFilter)
	actions, err = eng.Apply(ctx, actions, false, force)
	if err != nil {
		log.Printf("apply failed: %v", err)
		return false
	}
	printActions(actions, jsonOut)
	return !cycleFailed(actions)
}

func cycleFailed(actions []engine.Action) bool {
	for _, a := range actions {
		if a.Error != "" {
			return true
		}
	}
	return false
}

func runSchedule(eng *engine.Engine, at string, runNow bool, failureRetry time.Duration, domainFilter string, jsonOut, force bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("scheduler started: daily at %s (timezone %s), renew window %s", at, time.Local.String(), eng.Cfg.RenewBefore)
	for {
		ok := true
		if runNow {
			ok = runCycle(ctx, eng, domainFilter, jsonOut, force)
			if ok {
				log.Printf("scheduled run ok")
			} else {
				log.Printf("scheduled run finished with failures")
			}
		}
		var next time.Time
		if !ok && failureRetry > 0 {
			next = time.Now().Add(failureRetry)
			log.Printf("retrying failed run in %s", failureRetry)
		} else {
			next = nextDaily(at, time.Now())
			log.Printf("next run at %s", next.Format("2006-01-02 15:04:05 MST"))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		runNow = true
	}
}

func parseDailyAt(at string) (hour, minute int, err error) {
	parts := strings.Split(strings.TrimSpace(at), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("--at must be HH:MM, got %q", at)
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("--at must be HH:MM, got %q", at)
	}
	return h, m, nil
}

func nextDaily(at string, now time.Time) time.Time {
	h, m, _ := parseDailyAt(at)
	next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, time.Local)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

func runDoctor(eng *engine.Engine) {
	ctx := context.Background()
	ok := true
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			ok = false
			fmt.Printf("FAIL  %-12s %v\n", name, err)
		} else {
			fmt.Printf("OK    %s\n", name)
		}
	}

	check("1panel", func() error {
		certs, err := eng.Panel.ListCertificates(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("      %d certificates\n", len(certs))
		return nil
	})
	if eng.Qiniu != nil {
		check("qiniu", func() error {
			domains, err := eng.Qiniu.ListDomains(ctx)
			if err != nil {
				return err
			}
			certs, err := eng.Qiniu.ListCertificates(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("      %d domains, %d certificates\n", len(domains), len(certs))
			return nil
		})
	}
	if eng.Upyun != nil {
		check("upyun", func() error {
			domains, err := eng.Upyun.ListDomains(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("      %d domains\n", len(domains))
			for _, d := range domains {
				if strings.HasSuffix(d.Domain, ".test.upcdn.net") {
					continue
				}
				_, err = eng.Upyun.Bindings(ctx, d.Domain)
				return err
			}
			return nil
		})
	}
	if eng.UpyunConsole != nil {
		check("upyun-console", func() error {
			return eng.UpyunConsole.Login(ctx)
		})
	}
	if !ok {
		os.Exit(1)
	}
}

func runDaemon(eng *engine.Engine, interval time.Duration, domainFilter string, jsonOut, force bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		start := time.Now()
		log.Printf("daemon run started")
		ok := runCycle(ctx, eng, domainFilter, jsonOut, force)
		if !ok {
			log.Printf("daemon run finished with failures after %s", time.Since(start).Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func filterActions(actions []engine.Action, domains string) []engine.Action {
	want := map[string]bool{}
	for _, d := range strings.Split(domains, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			want[d] = true
		}
	}
	if len(want) == 0 {
		return actions
	}
	out := actions[:0]
	for _, a := range actions {
		if want[strings.ToLower(a.Domain)] {
			out = append(out, a)
		}
	}
	return out
}

func printActions(actions []engine.Action, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(actions)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tDOMAIN\tDECISION\tCURRENT EXPIRES\t1PANEL CERT\tREASON")
	for _, a := range actions {
		cur := a.CurrentExp
		if cur == "" {
			cur = "-"
		}
		target := "-"
		if a.TargetID != 0 {
			target = fmt.Sprintf("#%d %s", a.TargetID, a.TargetExp)
		}
		reason := a.Reason
		if a.Error != "" {
			reason = "ERROR: " + a.Error
		}
		if a.Applied && a.NewCertID != "" {
			reason = "applied; new cert " + a.NewCertID + " (" + a.CurrentExp + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Provider, a.Domain, a.Decision, cur, target, reason)
	}
	w.Flush()

	var updated, pending, healthy, problems int
	for _, a := range actions {
		switch {
		case a.Error != "":
			problems++
		case a.Applied:
			updated++
		case a.Decision == engine.DecisionSkip:
			healthy++
		case a.Decision == engine.DecisionRenew || a.Decision == engine.DecisionIssue:
			pending++
		default:
			problems++
		}
	}
	fmt.Printf("\n%d updated, %d pending, %d healthy, %d need attention\n", updated, pending, healthy, problems)
}

func needsAttention(actions []engine.Action) bool {
	for _, a := range actions {
		if a.Decision != engine.DecisionSkip {
			return true
		}
	}
	return false
}

func failed(actions []engine.Action, failOnUncovered bool) bool {
	for _, a := range actions {
		if a.Error != "" || a.Decision == engine.DecisionInvalid || a.Decision == engine.DecisionEdge {
			return true
		}
		if failOnUncovered && a.Decision == engine.DecisionNoCert {
			return true
		}
	}
	return false
}

func mustApply(actions []engine.Action) bool {
	for _, a := range actions {
		if a.Decision == engine.DecisionRenew || a.Decision == engine.DecisionIssue {
			return true
		}
	}
	return false
}

func parseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("window must be positive")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid window %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: use 30d or 720h", s)
	}
	return d, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `bercert - keep Qiniu/Upyun CDN certificates in sync with 1Panel

Usage:
  bercert doctor   [flags]  read-only check of 1Panel, Qiniu and Upyun credentials
  bercert scan     [flags]  report expiry and whether a 1Panel certificate can replace it
  bercert renew    [flags]  scan and apply replacements (use --dry-run first)
  bercert schedule [flags]  run once, then every day at --at in the server timezone
  bercert daemon   [flags]  run scan+renew every --interval
  bercert version

Flags:
  --env .env              env file (default .env)
  --renew-before 30d      renewal threshold
  --provider all          qiniu | upyun | all
  --domain a.com,b.com    restrict to domains
  --dry-run               renew: print actions without changing anything
  --force                 renew: replace even healthy certificates
  --issue                 request missing certificates from 1Panel
  --no-issue              never request certificates from 1Panel
  --retry-until-success   retry failed 1Panel issuance indefinitely
  --allow-uncovered       exit 0 when no 1Panel certificate covers a domain
  --at 04:17              schedule: daily time in server-local timezone
  --run-now               schedule: run at startup (default true)
  --failure-retry 10m     schedule: retry a failed run after this delay
  --interval 6h           daemon interval
  --json                  machine-readable output

Exit codes: 0 all healthy, 1 something needs attention or a change failed.
`)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
