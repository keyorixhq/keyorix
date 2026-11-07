package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Driver is one long-lived SDK driver process.
type Driver struct {
	Name string
	argv []string
	env  []string

	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func (d *Driver) start() error {
	cmd := exec.Command(d.argv[0], d.argv[1:]...) // #nosec G204 -- operator-built driver commands // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- argv is the operator's own driver command line for this test tool, not remote input
	cmd.Env = d.env
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	d.cmd, d.in, d.out = cmd, in, bufio.NewReaderSize(out, 1<<20)
	return nil
}

func (d *Driver) kill() {
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		_ = d.cmd.Wait()
	}
	d.cmd = nil
}

// call sends one protocol line and waits for one JSON line, restarting the driver on a hang.
func (d *Driver) call(line string, limit time.Duration) (map[string]any, error) {
	if d.cmd == nil {
		if err := d.start(); err != nil {
			return nil, err
		}
	}
	if _, err := io.WriteString(d.in, line+"\n"); err != nil {
		d.kill()
		return nil, fmt.Errorf("write: %w", err)
	}
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() { s, err := d.out.ReadString('\n'); ch <- res{s, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			d.kill()
			return nil, fmt.Errorf("read: %w", r.err)
		}
		dec := json.NewDecoder(io.LimitReader(strings.NewReader(r.s), maxJSONDoc))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("driver output not JSON: %v: %.200s", err, r.s)
		}
		return m, nil
	case <-time.After(limit):
		d.kill()
		return nil, fmt.Errorf("driver hang (> %s)", limit)
	}
}

// DriverSet knows how to launch each SDK kind.
type DriverSet struct {
	Root    string // sdkdiff directory (drivers/ lives below)
	Build   string // directory with built driver artefacts
	SDKsDir string // checkout of keyorix-sdks
	Plant   string
}

func kindOf(name string) string { k, _, _ := strings.Cut(name, "@"); return k }

func (ds DriverSet) make(name string) (*Driver, error) {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "SDKDIFF_SDKS_DIR=" + ds.SDKsDir, "SDKDIFF_PLANT=" + ds.Plant}
	var argv []string
	switch kindOf(name) {
	case "go":
		argv = []string{filepath.Join(ds.Build, "driver-go")}
	case "node":
		argv = []string{"node", filepath.Join(ds.Root, "drivers", "node", "driver.js")}
	case "python":
		argv = []string{"python3", "-u", "-I", filepath.Join(ds.Root, "drivers", "python", "driver.py")}
		env = append(env, "PYTHONDONTWRITEBYTECODE=1")
	case "java":
		argv = []string{javaBin(), "-Xshare:auto", "-XX:TieredStopAtLevel=1", "-cp", filepath.Join(ds.Build, "java-classes"), "Driver"}
	default:
		return nil, fmt.Errorf("unknown SDK kind %q", name)
	}
	return &Driver{Name: name, argv: argv, env: env}, nil
}

func javaBin() string {
	if p := os.Getenv("SDKDIFF_JAVA"); p != "" {
		return p
	}
	return "java"
}

// Runner executes scenarios for a set of SDKs.
type Runner struct {
	ServerBin string
	Snapshot  string
	Work      string
	DS        DriverSet
	SDKs      []string
	Par       int
	Shim      bool
	Mask      Masking
	Spec      *Spec

	drivers map[string]*Driver
	proxies map[string]*Proxy
}

func (r *Runner) init() error {
	r.drivers, r.proxies = map[string]*Driver{}, map[string]*Proxy{}
	for _, n := range r.SDKs {
		d, err := r.DS.make(n)
		if err != nil {
			return err
		}
		p, err := NewProxy()
		if err != nil {
			return err
		}
		p.Shim = r.Shim
		r.drivers[n], r.proxies[n] = d, p
	}
	return nil
}

// Close stops drivers and proxies.
func (r *Runner) Close() {
	for _, d := range r.drivers {
		d.kill()
	}
	for _, p := range r.proxies {
		p.Close()
	}
}

// RunBatch runs the scenarios for every SDK, each SDK on its own fresh server copy.
func (r *Runner) RunBatch(scs []Scenario) (map[string][]Outcome, error) {
	if r.drivers == nil {
		if err := r.init(); err != nil {
			return nil, err
		}
	}
	res := map[string][]Outcome{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, r.Par))
	var firstErr error
	for _, name := range r.SDKs {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outs, err := r.runSDK(name, scs)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", name, err)
			}
			res[name] = outs
		}(name)
	}
	wg.Wait()
	return res, firstErr
}

func (r *Runner) runSDK(name string, scs []Scenario) ([]Outcome, error) {
	inst, err := startFromSnapshot(r.ServerBin, r.Snapshot, r.Work)
	if err != nil {
		return nil, err
	}
	defer func() { inst.Stop(); _ = os.RemoveAll(inst.Dir) }()
	px, dr := r.proxies[name], r.drivers[name]
	px.SetUpstream(inst.BaseURL)
	var outs []Outcome
	for _, sc := range scs {
		o := runScenario(name, sc, inst, px, dr)
		o.Token = inst.Token
		outs = append(outs, o)
	}
	return outs, nil
}

const canaryToken = "CANARY-TOKEN-7f3a9c1d5e2b8a40" // #nosec G101 -- synthetic canary marker used to detect leaks, not a credential

func tokenFor(kind, good string) string {
	switch kind {
	case "", "good":
		return good
	case "empty":
		return ""
	case "canary":
		return canaryToken
	case "space":
		return " " + canaryToken
	case "crlf":
		return "abc\r\nX-Injected: 1"
	case "unicode":
		return "tökén-日本"
	case "long":
		return strings.Repeat("A", 65536)
	}
	return kind
}

func baseFor(kind, addr string) string {
	switch {
	case kind == "" || kind == "plain":
		return "http://" + addr
	case kind == "slash":
		return "http://" + addr + "/"
	case kind == "slash2":
		return "http://" + addr + "//"
	case kind == "upper_scheme":
		return "HTTP://" + addr
	case kind == "userinfo":
		return "http://u:p@" + addr
	case kind == "query":
		return "http://" + addr + "?x=1"
	case kind == "fragment":
		return "http://" + addr + "#frag"
	case kind == "prefix":
		return "http://" + addr + "/prefix"
	case strings.HasPrefix(kind, "literal:"):
		return strings.TrimPrefix(kind, "literal:")
	}
	return kind
}

func hexArg(a *string) string {
	if a == nil {
		return "~"
	}
	return hex.EncodeToString([]byte(*a))
}

func runScenario(sdk string, sc Scenario, inst *Instance, px *Proxy, dr *Driver) Outcome {
	out := Outcome{SDK: sdk}
	for i, st := range sc.Steps {
		args := make([]*string, len(st.Args))
		for j, a := range st.Args {
			switch {
			case a.Null:
				args[j] = nil
			case a.Ref != nil:
				s := resolveRef(out.Steps, a.Ref)
				args[j] = &s
			default:
				s := a.Str
				args[j] = &s
			}
		}
		base := baseFor(st.Base, px.Addr())
		tok := tokenFor(st.Token, inst.Token)
		parts := []string{st.Op, hex.EncodeToString([]byte(base)), hex.EncodeToString([]byte(tok)), strconv.Itoa(st.TimeoutMs)}
		for _, a := range args {
			parts = append(parts, hexArg(a))
		}
		px.Drain()
		px.SetFault(st.Fault)
		limit := 25 * time.Second
		if st.Fault != nil {
			limit += time.Duration(st.Fault.Ms) * time.Millisecond
		}
		d, err := dr.call(strings.Join(parts, "\t"), limit)
		recs := px.Drain()
		if err != nil {
			out.Failed = fmt.Sprintf("step %d: %v", i, err)
			out.Steps = append(out.Steps, StepOutcome{Reqs: recs})
			return out
		}
		out.Steps = append(out.Steps, StepOutcome{Drv: d, Reqs: recs})
	}
	return out
}

// resolveRef extracts "id" or "[0].id" style paths; an unresolved reference becomes "0".
func resolveRef(done []StepOutcome, ref *Ref) string {
	if ref.Step < 0 || ref.Step >= len(done) || done[ref.Step].Drv == nil {
		return "0"
	}
	v := done[ref.Step].Drv["value"]
	path := ref.Path
	if strings.HasPrefix(path, "[") {
		end := strings.Index(path, "]")
		idx, _ := strconv.Atoi(path[1:end])
		l, ok := v.([]any)
		if !ok || idx >= len(l) {
			return "0"
		}
		v = l[idx]
		path = strings.TrimPrefix(path[end+1:], ".")
	}
	if path != "" {
		m, ok := v.(map[string]any)
		if !ok {
			return "0"
		}
		v = m[path]
	}
	switch t := v.(type) {
	case json.Number:
		return t.String()
	case string:
		return t
	}
	return "0"
}

// Analyse turns per-SDK outcomes into findings for the scenario at index i.
func (r *Runner) Analyse(sc Scenario, outs map[string]Outcome) (findings []Finding, harness []string) {
	for sdk, o := range outs {
		if o.Failed != "" {
			harness = append(harness, fmt.Sprintf("H1 %s %s: %s", sc.ID, sdk, o.Failed))
		}
	}
	names := append([]string(nil), r.SDKs...)
	for i, st := range sc.Steps {
		var vs []view
		for _, n := range names {
			o, ok := outs[n]
			var so StepOutcome
			if ok && i < len(o.Steps) {
				so = o.Steps[i]
			}
			vs = append(vs, toView(n, so, r.Mask, o.Token))
		}
		part := compareStep(sc.ID, i, st.Op, vs)
		findings = append(findings, part...)
		findings = append(findings, absoluteChecks(sc.ID, i, st, vs, r.Spec, func(sdk string) string { return tokenFor(st.Token, outs[sdk].Token) })...)
		if len(part) > 0 {
			// later steps may depend on state diverged by this one
			break
		}
	}
	return
}
