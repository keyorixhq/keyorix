package configspace

import (
	"fmt"
	"strings"
)

// warnLines returns the log lines that look like warnings.
func warnLines(log string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "warn") {
			out = append(out, l)
		}
	}
	return out
}

func explicitlyWritten(c *Case, rule *PostureRule) bool {
	for _, k := range rule.Explicit {
		if _, ok := GetPath(c.Doc, k); ok {
			return true
		}
	}
	return false
}

func canaryTail(val string) string {
	if len(val) > 12 {
		return val[len(val)-12:]
	}
	return val
}

// CheckProc applies the process-level invariants to one result.
func CheckProc(m *Model, c *Case, ip InProcResult, pr ProcResult) []Finding {
	var fs []Finding
	add := func(inv, sev, key, title, detail string) {
		fs = append(fs, Finding{Inv: inv, Sev: sev, Stage: "proc", Case: c.ID, Key: key, Title: title, Detail: detail})
	}
	// I1
	lowLog := pr.Log
	if pr.Signal != "" || strings.Contains(lowLog, "panic: ") || strings.Contains(lowLog, "fatal error: ") {
		sev := "S3"
		if pr.Started {
			sev = "S2"
		}
		add("I1", sev, "proc-crash:"+firstAssign(c), "server crashed (signal or panic)", tail(lowLog, 600))
	}
	if pr.TimedOut {
		add("I1", "S3", "proc-hang:"+firstAssign(c), "server neither started nor exited in time", tail(lowLog, 400))
	}
	// I4: canaries anywhere a client or operator can read.
	surfaces := map[string]string{"log": pr.Log}
	for k, v := range pr.Bodies {
		surfaces["http "+k[strings.LastIndex(k, "/"):]] = v
	}
	for k, v := range pr.Admin {
		surfaces["admin "+k] = v
	}
	for val, name := range c.Canaries {
		tail12 := canaryTail(val)
		for where, text := range surfaces {
			if strings.Contains(text, tail12) {
				add("I4", "S1", "leak:"+name+":"+where, "secret value found in "+where, "canary "+name)
			}
		}
	}
	faults := m.Faults(c)
	conflicts := m.TriggeredConflicts(c)
	var tokens []string
	for _, p := range faults {
		tokens = append(tokens, tokensFor(p)...)
	}
	for _, cf := range conflicts {
		tokens = append(tokens, cf.Names...)
	}
	refused := !pr.Started && !pr.TimedOut && pr.Signal == ""
	if refused {
		if pr.Exit == 0 {
			add("I2", "S3", "refusal-exit0:"+firstAssign(c), "refused to start but exited 0", tail(pr.Log, 400))
		}
		if len(tokens) > 0 && !errNames(pr.Log, tokens) {
			add("I2", "S3", "proc-refusal-unnamed:"+firstAssign(c), "refusal does not name the offending option", tail(pr.Log, 400))
		}
		if len(tokens) == 0 && ip.Accepted {
			// a boot-time refusal the in-process check did not predict: informational
			add("I2", "S4", "boot-refusal:"+firstAssign(c), "boot refused a configuration Load+Validate accepted", tail(pr.Log, 300))
		}
		return fs
	}
	if !pr.Started {
		return fs
	}
	// started
	if !ip.Accepted && !ip.LoadFailed {
		add("I2", "S2", "started-but-validate-refused:"+firstAssign(c), "server started although Validate refuses the configuration", ip.Err)
	}
	if ip.LoadFailed {
		add("I2", "S2", "started-but-load-failed:"+firstAssign(c), "server started although Load refuses the configuration", ip.Err)
	}
	for _, cf := range conflicts {
		add("I2", "S2", "proc-conflict-started:"+cf.ID, "contradictory combination started ("+cf.ID+")", fmt.Sprint(cf.When))
	}
	if len(faults) == 1 && ip.Accepted {
		p := faults[0]
		v := p.Values[c.Assign[p.ID]]
		if v.Fallback == "" {
			add("I2", "S2", "proc-invalid-started:"+p.ID+":"+fmt.Sprint(v.V), "invalid value started ("+p.Path+")", fmt.Sprint(v.V))
		}
	}
	// I6
	for base, code := range pr.Health {
		if code != 200 {
			add("I6", "S3", "health:"+firstAssign(c), "health check did not return 200 on "+base[:strings.LastIndex(base, ":")], fmt.Sprint(code))
		}
	}
	if !pr.ShutdownOK {
		add("I6", "S3", "shutdown:"+firstAssign(c), "no clean exit 0 after SIGTERM", fmt.Sprintf("exit %d signal %q timed out %v", pr.Exit, pr.Signal, pr.TimedOut))
	} else if !pr.Graceful {
		add("I6", "S4", "shutdown-line:"+firstAssign(c), "exit 0 but no graceful-shutdown log line", "")
	}
	// I3(b): every posture predicate that holds must be warned about at start
	wl := warnLines(pr.Log)
	for _, id := range ip.Posture {
		rule := m.PostureRule(id)
		hit := false
		for _, l := range wl {
			if rule.warnRE.MatchString(l) {
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		sev := "S2"
		if !explicitlyWritten(c, rule) {
			sev = "S1"
		}
		add("I3", sev, "no-warning:"+id, "insecure posture "+id+" ("+rule.What+") started without a matching warning", "explicit key written: "+fmt.Sprint(explicitlyWritten(c, rule)))
	}
	return fs
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
