package main

// Orchestrator, oracles and reports of the hostile-server mode (hostile/RULES.md).

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	hCallTimeoutMs = 5000
	hWallDeadline  = 12 * time.Second
	hHardKill      = 25 * time.Second
	hRSSCeilingKB  = 1 << 20 // 1 GiB
)

// hMaxLine bounds one driver answer line held in memory. It is above the largest value an X mutation must get back
// exactly (U19, 16 MiB) and far below what an SDK that accepts B01/B02/U20 would print; longer lines are drained
// without being kept (Reason "oversize"), so four drivers in parallel cannot exhaust the harness's memory.
var hMaxLine = 32 << 20

// ---- driver process with RSS monitoring ----

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b.Len() < 1<<20 {
		s.b.Write(p)
	}
	return len(p), nil
}

func (s *syncBuf) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.b.String()
	s.b.Reset()
	return v
}

// HDriver is a long-lived SDK driver for the hostile mode.
type HDriver struct {
	name   string
	argv   []string
	env    []string
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *syncBuf
	waitCh chan error
}

func hostileDriver(name, root, build, sdks string) (*HDriver, error) {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "SDKDIFF_SDKS_DIR=" + sdks, "SDKDIFF_PLANT=", "SDKDIFF_HOSTILE=1"}
	var argv []string
	switch kindOf(name) {
	case "go":
		argv = []string{filepath.Join(build, "driver-go")}
		env = append(env, "GOMAXPROCS=2")
	case "node":
		argv = []string{"node", "--max-old-space-size=512", filepath.Join(root, "drivers", "node", "driver.js")}
	case "python":
		argv = []string{"python3", "-u", "-I", filepath.Join(root, "drivers", "python", "driver.py")}
		env = append(env, "PYTHONDONTWRITEBYTECODE=1")
	case "java":
		argv = []string{javaBin(), "-Xmx512m", "-Xshare:auto", "-XX:TieredStopAtLevel=1", "-cp", filepath.Join(build, "java-classes"), "Driver"}
	default:
		return nil, fmt.Errorf("unknown SDK kind %q", name)
	}
	argv = append([]string{"nice", "-n", "10"}, argv...)
	return &HDriver{name: name, argv: argv, env: env, stderr: &syncBuf{}}, nil
}

func (d *HDriver) start() error {
	cmd := exec.Command(d.argv[0], d.argv[1:]...) // #nosec G204 -- operator-built driver commands // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Env = d.env
	cmd.Stderr = d.stderr
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
	d.waitCh = make(chan error, 1)
	go func() { d.waitCh <- cmd.Wait() }()
	return nil
}

func (d *HDriver) kill() {
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		select {
		case err := <-d.waitCh:
			_ = err
		case <-time.After(5 * time.Second):
		}
	}
	d.cmd = nil
}

func rssKB(pid int) int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output() // #nosec G204 -- own child pid
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return v
}

type callInfo struct {
	Elapsed time.Duration
	PeakKB  int64
	Reason  string // "" | hang | rss | died | badout (answer not JSON) | oversize (answer longer than hMaxLine)
	Exit    string
	Stderr  string
}

// readLineMax reads one '\n'-terminated line. A line longer than max is consumed up to its end but not kept
// (over is true), so the protocol stays in step and memory stays bounded.
func readLineMax(r *bufio.Reader, max int) (line string, over bool, err error) {
	var b []byte
	for {
		frag, err := r.ReadSlice('\n')
		if !over {
			if len(b)+len(frag) > max {
				over, b = true, nil
			} else {
				b = append(b, frag...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(b), over, err
	}
}

func (d *HDriver) call(line string) (map[string]any, callInfo) {
	var info callInfo
	if d.cmd == nil {
		if err := d.start(); err != nil {
			info.Reason, info.Exit = "died", "start: "+err.Error()
			return nil, info
		}
	}
	d.stderr.take()
	t0 := time.Now()
	if _, err := io.WriteString(d.in, line+"\n"); err != nil {
		d.kill()
		info.Reason, info.Exit = "died", "write: "+err.Error()
		return nil, info
	}
	type res struct {
		s    string
		over bool
		err  error
	}
	ch := make(chan res, 1)
	go func() { s, over, err := readLineMax(d.out, hMaxLine); ch <- res{s, over, err} }()
	var peak atomic.Int64
	var reason atomic.Value
	stop := make(chan struct{})
	pid := d.cmd.Process.Pid
	var mwg sync.WaitGroup
	mwg.Go(func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				r := rssKB(pid)
				if r > peak.Load() {
					peak.Store(r)
				}
				if r > hRSSCeilingKB {
					reason.Store("rss")
					_ = d.cmd.Process.Kill()
					return
				}
			}
		}
	})
	var r res
	select {
	case r = <-ch:
	case <-time.After(hHardKill):
		reason.Store("hang")
		_ = d.cmd.Process.Kill()
		r = <-ch
	}
	if last := rssKB(pid); last > peak.Load() {
		peak.Store(last)
	}
	close(stop)
	mwg.Wait()
	info.Elapsed = time.Since(t0)
	info.PeakKB = peak.Load()
	if v, ok := reason.Load().(string); ok {
		info.Reason = v
	}
	if r.err != nil {
		if info.Reason == "" {
			info.Reason = "died"
		}
		select {
		case err := <-d.waitCh:
			info.Exit = fmt.Sprint(err)
		case <-time.After(3 * time.Second):
		}
		d.cmd = nil
		info.Stderr = d.stderr.take()
		return nil, info
	}
	info.Stderr = d.stderr.take()
	if r.over {
		info.Reason, info.Exit = "oversize", fmt.Sprintf("driver answer longer than %d bytes, discarded", hMaxLine)
		return nil, info
	}
	dec := json.NewDecoder(strings.NewReader(r.s)) // nosemgrep: semgrep.keyorix-unbounded-json-decoder -- r.s is already capped at hMaxLine above
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		// Something other than the driver wrote to stdout; the real answer may still be in the pipe, so start over.
		d.kill()
		info.Reason, info.Exit = "badout", "driver output not JSON: "+trunc(r.s, 200)
		return nil, info
	}
	if m["abandoned"] == true {
		// The Node driver answered for a call whose SDK work is still running (a side event fired and the call did
		// not settle). Restart it so that work cannot reach the next call's session.
		d.kill()
	}
	return m, info
}

// ---- records and oracles ----

// Viol is one oracle violation.
type Viol struct {
	Oracle string `json:"oracle"`
	Sev    string `json:"sev"`
	Detail string `json:"detail"`
}

// RunRec is the record of one (SDK, scenario, mutation) call.
type RunRec struct {
	SDK     string         `json:"sdk"`
	Scen    string         `json:"scen"`
	Mut     string         `json:"mut"`
	Applied string         `json:"applied"` // applied | n/a | not-reached
	Outcome string         `json:"outcome"` // ok | err:<class> | na | died | hang | rss
	Exp     string         `json:"exp"`
	Native  string         `json:"native,omitempty"`
	Msg     string         `json:"msg,omitempty"`
	Viol    []Viol         `json:"viol,omitempty"`
	Notes   []string       `json:"notes,omitempty"`
	Ms      int64          `json:"ms"`
	PeakMB  int64          `json:"peak_mb"`
	Reqs    []string       `json:"reqs,omitempty"`
	Val     string         `json:"val,omitempty"`
	Drv     map[string]any `json:"-"`
}

const canary = "CANARY-TOKEN-7f3a9c1d5e2b8a40"

func sevFor(sc *HScen, m *Mut) string {
	if m.Low {
		return "LOW"
	}
	if sc.Target == "V" || sc.Target == "A" {
		return "HIGH"
	}
	return "MEDIUM"
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

var (
	rePathEnv = regexp.MustCompile(`^/api/v1/projects/(\d+)/environments`)
	reQueryEn = regexp.MustCompile(`environment_id=(\d+)`)
	rePathSec = regexp.MustCompile(`^/api/v1/secrets/(\d+)`)
)

// observedID returns the id forwarded to the request that follows the mutated one (scenarios S11-S13).
func observedID(sc *HScen, reqs []HReq) (string, bool) {
	for _, r := range reqs {
		switch sc.ID {
		case "S11":
			if r.Class == "E" {
				if m := rePathEnv.FindStringSubmatch(strings.SplitN(r.URI, "?", 2)[0]); m != nil {
					return m[1], true
				}
			}
		case "S12":
			if r.Class == "L" {
				if m := reQueryEn.FindStringSubmatch(r.URI); m != nil {
					return m[1], true
				}
			}
		case "S13":
			if r.Class == "V" {
				if m := rePathSec.FindStringSubmatch(strings.SplitN(r.URI, "?", 2)[0]); m != nil {
					return m[1], true
				}
			}
		}
	}
	return "", false
}

func firstOf(v any) map[string]any {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return nil
	}
	m, _ := l[0].(map[string]any)
	return m
}

func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func leaksToken(s string) bool {
	return strings.Contains(s, canary) || strings.Contains(s, strings.ReplaceAll(canary, "-", "%2D"))
}

// judge applies the oracles of RULES.md section 4 to one call.
func judge(sc *HScen, m *Mut, drv map[string]any, info callInfo, reqs []HReq, golden map[string]any) (rec RunRec) {
	rec.Scen, rec.Mut, rec.Exp = sc.ID, m.ID, m.Exp
	rec.Ms, rec.PeakMB = info.Elapsed.Milliseconds(), info.PeakKB/1024
	var mreq *HReq
	targetSeen := false
	for i := range reqs {
		rec.Reqs = append(rec.Reqs, reqs[i].Method+" "+trunc(reqs[i].URI, 80))
		if reqs[i].Class == sc.Target {
			targetSeen = true
		}
		if reqs[i].Mutated && mreq == nil {
			mreq = &reqs[i]
		}
	}
	switch {
	case mreq != nil:
		rec.Applied = "applied"
	case targetSeen:
		rec.Applied = "n/a"
	default:
		rec.Applied = "not-reached"
	}
	exp := m.Exp
	if m.ID == "H09" && mreq != nil && mreq.AcceptGzip {
		exp = "A"
	}
	if sc.ID == "S01" && m.Family != "S" && m.ID != "R03" && m.ID != "R04" && !m.Ctl {
		exp = "E" // health reads the status only (RULES amendment A1)
	}
	if sc.ID == "S02" && exp == "X" {
		exp = "E" // login returns only the token length
	}
	rec.Exp = exp
	add := func(o, sev, d string) { rec.Viol = append(rec.Viol, Viol{o, sev, trunc(d, 300)}) }

	// harness-level reasons first
	if drv == nil {
		switch info.Reason {
		case "hang":
			rec.Outcome = "hang"
			add("O2", "MEDIUM", fmt.Sprintf("no answer within %s, driver killed (peak %d MB)", hHardKill, info.PeakKB/1024))
		case "rss":
			rec.Outcome = "rss"
			add("O2", "MEDIUM", fmt.Sprintf("RSS above %d MB, driver killed (peak %d MB)", hRSSCeilingKB/1024, info.PeakKB/1024))
		case "badout", "oversize":
			// the driver is alive (or was restarted by the harness): a harness record, not an O1 crash
			rec.Outcome = "harness"
			rec.Notes = append(rec.Notes, "H2 "+info.Reason+": "+trunc(info.Exit, 200))
		default:
			rec.Outcome = "died"
			add("O1", "MEDIUM", "driver process exited during the call: "+trunc(info.Exit+" "+info.Stderr, 250))
		}
		if leaksToken(info.Stderr) {
			if m.ID == "S13m" {
				rec.Notes = append(rec.Notes, "O4r token reflected from the server body in stderr")
			} else {
				add("O4", "HIGH", "token in stderr: "+trunc(info.Stderr, 120))
			}
		}
		if rec.Applied != "applied" {
			rec.Viol = nil
		}
		return
	}
	rec.Drv = drv
	if ev, _ := drv["late_side_events"].([]any); len(ev) > 0 {
		// fired in the context of an earlier, already answered call: noted here, not judged against this call
		rec.Notes = append(rec.Notes, fmt.Sprintf("H3 %d late side event(s) of an earlier call: %s", len(ev), trunc(str(ev[0]), 200)))
	}
	if _, ok := drv["driver_error"]; ok {
		rec.Outcome = "harness"
		rec.Notes = append(rec.Notes, "H1 driver_error: "+trunc(str(drv["driver_error"]), 200))
		return
	}
	if drv["na"] == true || drv["inexpressible"] == true {
		rec.Outcome = "na"
		return
	}
	ok := drv["ok"] == true
	if ok {
		rec.Outcome = "ok"
		rec.Val = trunc(canon(drv["value"]), 120)
	} else {
		rec.Outcome = "err:" + str(drv["class"])
		rec.Native, rec.Msg = str(drv["native"]), trunc(str(drv["msg"]), 200)
	}
	if rec.Applied != "applied" {
		return
	}
	if info.Elapsed > hWallDeadline {
		add("O2", "LOW", fmt.Sprintf("returned after %.1fs (deadline %s) with %s", info.Elapsed.Seconds(), hWallDeadline, rec.Outcome))
	}
	if info.PeakKB > hRSSCeilingKB {
		add("O2", "MEDIUM", fmt.Sprintf("peak RSS %d MB above %d MB", info.PeakKB/1024, hRSSCeilingKB/1024))
	}
	if ev, _ := drv["side_events"].([]any); len(ev) > 0 {
		add("O1", "MEDIUM", "side event: "+trunc(str(ev[0]), 200))
	}
	if !ok && drv["sdk_error"] == false {
		add("O1", "MEDIUM", fmt.Sprintf("non-SDK error type %s: %s", rec.Native, trunc(str(drv["msg"]), 150)))
	}
	// O4. S13m's server body echoes the Authorization header, so a token anywhere in the SDK's output for that
	// mutation is reflection, reported as the informational O4r (RULES.md section 4, amendment A11).
	o4 := func(where, v string) bool {
		if !leaksToken(v) {
			return false
		}
		if m.ID == "S13m" {
			rec.Notes = append(rec.Notes, "O4r token reflected from the server body in "+where)
		} else {
			add("O4", "HIGH", "token in "+where+": "+trunc(v, 160))
		}
		return true
	}
	for _, f := range []string{"msg", "native", "full"} {
		if o4(f, str(drv[f])) {
			break
		}
	}
	o4("stderr", info.Stderr)
	sev := sevFor(sc, m)
	switch exp {
	case "R":
		if ok {
			add("O3", sev, "success returned for a mutated response: "+rec.Val)
		}
	case "X":
		checkExact(sc, m, drv, ok, reqs, add, sev)
	case "A":
		if !ok {
			rec.Notes = append(rec.Notes, "unexpected rejection: "+rec.Outcome+" "+rec.Msg)
		} else if golden != nil && canon(golden["value"]) != canon(drv["value"]) {
			add("O3", "MEDIUM", "benign variant changed the result: "+rec.Val)
		}
	}
	if m.WantID != "" && (sc.ID == "S11" || sc.ID == "S12" || sc.ID == "S13") {
		checkForward(sc, m, reqs, add)
	}
	return
}

func checkForward(sc *HScen, m *Mut, reqs []HReq, add func(o, sev, d string)) {
	got, seen := observedID(sc, reqs)
	if !seen {
		return
	}
	if m.WantID == "!" || got != m.WantID {
		add("O6", "MEDIUM", fmt.Sprintf("id forwarded as %s, server sent %s", trunc(got, 40), trunc(m.WantID, 40)))
	}
}

func checkExact(sc *HScen, m *Mut, drv map[string]any, ok bool, reqs []HReq, add func(o, sev, d string), sev string) {
	if !ok {
		return
	}
	v := drv["value"]
	if m.WantID != "" {
		var got string
		switch sc.ID {
		case "S04":
			if mm, _ := v.(map[string]any); mm != nil {
				got = str(mm["id"])
			}
		case "S11", "S12", "S13":
			return // judged on the forwarded id
		default:
			if it := firstOf(v); it != nil {
				got = str(it["id"])
			}
		}
		if m.WantID == "!" || got != m.WantID {
			add("O6", "MEDIUM", fmt.Sprintf("returned id %s, server sent %s", trunc(got, 40), trunc(m.WantID, 40)))
		}
		return
	}
	want := m.wantMain()
	if want == "" {
		return
	}
	var got string
	switch {
	case sc.Target == "V":
		got = str(v)
	case sc.ID == "S04":
		if mm, _ := v.(map[string]any); mm != nil {
			got = str(mm["name"])
		}
	default:
		if it := firstOf(v); it != nil {
			got = str(it["name"])
		}
	}
	if got != want {
		add("O3", sev, fmt.Sprintf("returned %q, server sent %q", trunc(got, 60), trunc(want, 60)))
	}
}

// ---- running ----

func hexs(s string) string { return hex.EncodeToString([]byte(s)) }

type hostileCfg struct {
	sdks, sdksDir, build, root, out, muts, scens, label string
	par                                                 int
}

func (c *hostileCfg) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.sdks, "sdks", "go,node,python,java", "SDK drivers to run")
	fs.StringVar(&c.sdksDir, "sdks-dir", "", "keyorix-sdks checkout (or plant copy)")
	fs.StringVar(&c.build, "build", "", "built driver artefacts (build-drivers.sh)")
	fs.StringVar(&c.root, "root", ".", "sdkdiff source dir")
	fs.StringVar(&c.out, "out", "out-hostile", "output dir")
	fs.StringVar(&c.muts, "mut", "", "comma list of mutation ids or id prefixes (default all)")
	fs.StringVar(&c.scens, "scen", "", "comma list of scenario ids (default per mutation)")
	fs.IntVar(&c.par, "par", 4, "SDKs in parallel")
	fs.StringVar(&c.label, "label", "", "label recorded in the report header")
}

func selectMuts(sel string) []*Mut {
	var out []*Mut
	for i := range muts {
		if sel == "" {
			out = append(out, &muts[i])
			continue
		}
		for p := range strings.SplitSeq(sel, ",") {
			if p != "" && strings.HasPrefix(muts[i].ID, p) {
				out = append(out, &muts[i])
				break
			}
		}
	}
	return out
}

type job struct {
	sc *HScen
	m  *Mut
}

func buildJobs(ms []*Mut, scSel string) []job {
	want := map[string]bool{}
	for s := range strings.SplitSeq(scSel, ",") {
		if s != "" {
			want[s] = true
		}
	}
	var jobs []job
	for _, m := range ms {
		for _, sid := range m.Scens {
			if len(want) > 0 && !want[sid] {
				continue
			}
			jobs = append(jobs, job{scenByID(sid), m})
		}
	}
	return jobs
}

func runOne(d *HDriver, srv *HostSrv, sc *HScen, m *Mut, golden map[string]any) RunRec {
	se := newSession(m, sc.Target)
	srv.Arm(se)
	parts := []string{sc.Op, hexs("http://" + srv.Addr()), hexs(canary), strconv.Itoa(hCallTimeoutMs)}
	for _, a := range sc.Args {
		parts = append(parts, hexs(a))
	}
	drv, info := d.call(strings.Join(parts, "\t"))
	reqs := srv.Disarm()
	rec := judge(sc, m, drv, info, reqs, golden)
	return rec
}

func trimDrv(rec *RunRec) { rec.Drv = nil }

// runSDK runs all jobs for one SDK and sends the records.
func runSDK(cfg *hostileCfg, name string, jobs []job, out chan<- RunRec) error {
	srv, err := NewHostSrv()
	if err != nil {
		return err
	}
	defer srv.Close()
	d, err := hostileDriver(name, cfg.root, cfg.build, cfg.sdksDir)
	if err != nil {
		return err
	}
	defer d.kill()
	golden := map[string]map[string]any{}
	c0 := mutByID("C0")
	for i := range hscens {
		sc := &hscens[i]
		rec := runOne(d, srv, sc, c0, nil)
		rec.SDK = name
		if rec.Drv != nil && rec.Drv["ok"] == true {
			golden[sc.ID] = rec.Drv
		}
		trimDrv(&rec)
		out <- rec
	}
	for i, j := range jobs {
		if j.m.ID == "C0" {
			continue
		}
		if i%100 == 99 {
			fmt.Fprintf(os.Stderr, "%s %s %d/%d (%s %s)\n", time.Now().Format("15:04:05"), name, i+1, len(jobs), j.m.ID, j.sc.ID)
		}
		rec := runOne(d, srv, j.sc, j.m, golden[j.sc.ID])
		rec.SDK = name
		trimDrv(&rec)
		out <- rec
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func runMatrix(cfg *hostileCfg, jobs []job) ([]RunRec, error) {
	sdks := strings.Split(cfg.sdks, ",")
	out := make(chan RunRec, 64)
	var recs []RunRec
	var rmu sync.WaitGroup
	rmu.Go(func() {
		for r := range out {
			recs = append(recs, r)
		}
	})
	sem := make(chan struct{}, max(1, cfg.par))
	var wg sync.WaitGroup
	var firstErr error
	var emu sync.Mutex
	for _, n := range sdks {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := runSDK(cfg, n, jobs, out); err != nil {
				emu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", n, err)
				}
				emu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	close(out)
	rmu.Wait()
	return recs, firstErr
}

func cmdHostile(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sdkdiff hostile run|replay|diff|list [flags]")
	}
	switch args[0] {
	case "list":
		for _, m := range muts {
			fmt.Printf("%-5s %s exp=%s scens=%s  %s\n", m.ID, m.Family, m.Exp, strings.Join(m.Scens, ","), m.Desc)
		}
		return nil
	case "run":
		return hostileRun(args[1:])
	case "replay":
		return hostileReplay(args[1:])
	case "diff":
		return hostileDiff(args[1:])
	case "jsontable":
		return cmdJSONTable(args[1:])
	}
	return fmt.Errorf("unknown hostile command %q", args[0])
}

func absAll(ps ...*string) {
	for _, p := range ps {
		if *p != "" {
			if a, err := filepath.Abs(*p); err == nil {
				*p = a
			}
		}
	}
}

func writeResults(cfg *hostileCfg, recs []RunRec) error {
	if err := os.MkdirAll(cfg.out, 0o750); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(cfg.out, "results.jsonl")) // #nosec G304 -- operator path
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	w := bufio.NewWriter(f)
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].SDK != recs[j].SDK {
			return recs[i].SDK < recs[j].SDK
		}
		if recs[i].Mut != recs[j].Mut {
			return recs[i].Mut < recs[j].Mut
		}
		return recs[i].Scen < recs[j].Scen
	})
	for _, r := range recs {
		b, _ := json.Marshal(r)
		_, _ = w.Write(append(b, '\n'))
	}
	return w.Flush()
}

func hostileRun(args []string) error {
	var cfg hostileCfg
	fs := flag.NewFlagSet("hostile run", flag.ExitOnError)
	cfg.flags(fs)
	_ = fs.Parse(args)
	absAll(&cfg.sdksDir, &cfg.build, &cfg.root, &cfg.out)
	jobs := buildJobs(selectMuts(cfg.muts), cfg.scens)
	fmt.Printf("hostile run: %d jobs per SDK, sdks=%s sdks-dir=%s label=%s\n", len(jobs), cfg.sdks, cfg.sdksDir, cfg.label)
	t0 := time.Now()
	recs, err := runMatrix(&cfg, jobs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run error:", err)
	}
	if werr := writeResults(&cfg, recs); werr != nil {
		return werr
	}
	rep := report(recs, cfg.label, time.Since(t0))
	_ = os.WriteFile(filepath.Join(cfg.out, "report.txt"), []byte(rep), 0o600) // #nosec G306 -- operator path
	fmt.Print(rep)
	return err
}

// ---- report ----

func report(recs []RunRec, label string, took time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "== hostile report %s (%.0fs, %d records)\n", label, took.Seconds(), len(recs))
	sdks := map[string]bool{}
	for _, r := range recs {
		sdks[r.SDK] = true
	}
	names := keys(sdks)
	type cnt struct{ runs, applied, ok, errs, na, nr int }
	cs := map[string]*cnt{}
	vc := map[string]map[string]int{}
	for _, r := range recs {
		c := cs[r.SDK]
		if c == nil {
			c = &cnt{}
			cs[r.SDK] = c
			vc[r.SDK] = map[string]int{}
		}
		c.runs++
		switch r.Applied {
		case "applied":
			c.applied++
			if r.Outcome == "ok" {
				c.ok++
			} else {
				c.errs++
			}
		case "n/a":
			c.na++
		default:
			c.nr++
		}
		for _, v := range r.Viol {
			vc[r.SDK][v.Oracle]++
		}
	}
	for _, n := range names {
		c := cs[n]
		fmt.Fprintf(&b, "%-7s runs=%d applied=%d (ok=%d err/other=%d) n/a=%d not-reached=%d violations:", n, c.runs, c.applied, c.ok, c.errs, c.na, c.nr)
		for _, o := range keys(boolMap(vc[n])) {
			fmt.Fprintf(&b, " %s=%d", o, vc[n][o])
		}
		b.WriteString("\n")
	}
	// violations grouped by (sdk, oracle, mutation)
	type gk struct{ sdk, oracle, mut, sev string }
	groups := map[gk][]string{}
	detail := map[gk]string{}
	for _, r := range recs {
		for _, v := range r.Viol {
			k := gk{r.SDK, v.Oracle, r.Mut, v.Sev}
			groups[k] = append(groups[k], r.Scen)
			if _, ok := detail[k]; !ok {
				detail[k] = v.Detail
			}
		}
	}
	var gks []gk
	for k := range groups {
		gks = append(gks, k)
	}
	sevRank := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}
	sort.Slice(gks, func(i, j int) bool {
		a, c := gks[i], gks[j]
		if sevRank[a.sev] != sevRank[c.sev] {
			return sevRank[a.sev] < sevRank[c.sev]
		}
		if a.oracle != c.oracle {
			return a.oracle < c.oracle
		}
		if a.mut != c.mut {
			return a.mut < c.mut
		}
		return a.sdk < c.sdk
	})
	b.WriteString("\n-- violations (sev oracle mutation sdk: scenarios | first detail)\n")
	for _, k := range gks {
		fmt.Fprintf(&b, "%-6s %s %-5s %-7s %s | %s\n", k.sev, k.oracle, k.mut, k.sdk, strings.Join(groups[k], ","), trunc(detail[k], 140))
	}
	// O5: ok/err disagreement on R, X and A mutations
	type pk struct{ scen, mut string }
	outcomes := map[pk]map[string]string{}
	exps := map[pk]string{}
	for _, r := range recs {
		if r.Applied != "applied" || r.Outcome == "na" || r.Outcome == "harness" {
			continue
		}
		k := pk{r.Scen, r.Mut}
		if outcomes[k] == nil {
			outcomes[k] = map[string]string{}
		}
		outcomes[k][r.SDK] = r.Outcome
		exps[k] = r.Exp
	}
	var pks []pk
	for k, o := range outcomes {
		if len(o) < 2 {
			continue
		}
		seen := map[bool]bool{}
		for _, v := range o {
			seen[v == "ok"] = true
		}
		if len(seen) > 1 {
			pks = append(pks, k)
		}
	}
	sort.Slice(pks, func(i, j int) bool {
		if pks[i].mut != pks[j].mut {
			return pks[i].mut < pks[j].mut
		}
		return pks[i].scen < pks[j].scen
	})
	fmt.Fprintf(&b, "\n-- O5 ok/err disagreements across SDKs: %d (scenario, mutation) pairs\n", len(pks))
	for _, k := range pks {
		var parts []string
		for _, n := range keys(boolMap2(outcomes[k])) {
			parts = append(parts, n+"="+outcomes[k][n])
		}
		fmt.Fprintf(&b, "%-5s %-4s exp=%s %s\n", k.mut, k.scen, exps[k], strings.Join(parts, " "))
	}
	var notes []string
	for _, r := range recs {
		for _, n := range r.Notes {
			if reHarnessNote.MatchString(n) || strings.HasPrefix(n, "O4r") || strings.HasPrefix(n, "unexpected rejection") && isCtl(r.Mut) {
				notes = append(notes, fmt.Sprintf("%s %s %s: %s", r.SDK, r.Scen, r.Mut, trunc(n, 160)))
			}
		}
	}
	fmt.Fprintf(&b, "\n-- harness notes, O4r reflections and control rejections: %d\n", len(notes))
	for i, n := range notes {
		if i >= 60 {
			b.WriteString("...\n")
			break
		}
		b.WriteString(n + "\n")
	}
	return b.String()
}

var reHarnessNote = regexp.MustCompile(`^H\d `)

func isCtl(id string) bool {
	m := mutByID(id)
	return m != nil && m.Ctl
}

func keys(m map[string]bool) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

func boolMap(m map[string]int) map[string]bool {
	o := map[string]bool{}
	for k := range m {
		o[k] = true
	}
	return o
}

func boolMap2(m map[string]string) map[string]bool {
	o := map[string]bool{}
	for k := range m {
		o[k] = true
	}
	return o
}

// ---- replay and diff ----

func sigOf(r RunRec) string {
	var vs []string
	for _, v := range r.Viol {
		vs = append(vs, v.Oracle+":"+v.Sev)
	}
	sort.Strings(vs)
	return r.Applied + "|" + strings.Split(r.Outcome, ":")[0] + "|" + strings.Join(vs, ",")
}

func hostileReplay(args []string) error {
	var cfg hostileCfg
	fs := flag.NewFlagSet("hostile replay", flag.ExitOnError)
	cfg.flags(fs)
	triples := fs.String("triples", "", "comma list sdk:scenario:mutation")
	n := fs.Int("n", 3, "repetitions")
	_ = fs.Parse(args)
	absAll(&cfg.sdksDir, &cfg.build, &cfg.root, &cfg.out)
	by := map[string][]string{}
	for t := range strings.SplitSeq(*triples, ",") {
		p := strings.Split(t, ":")
		if len(p) != 3 {
			return fmt.Errorf("bad triple %q", t)
		}
		by[p[0]] = append(by[p[0]], p[1]+":"+p[2])
	}
	for sdk, list := range by {
		if err := replaySDK(&cfg, sdk, list, *n); err != nil {
			return err
		}
	}
	return nil
}

// replaySDK replays the (scenario, mutation) pairs of one SDK; the server and the driver are released on every return.
func replaySDK(cfg *hostileCfg, sdk string, list []string, n int) error {
	srv, err := NewHostSrv()
	if err != nil {
		return err
	}
	defer srv.Close()
	d, err := hostileDriver(sdk, cfg.root, cfg.build, cfg.sdksDir)
	if err != nil {
		return err
	}
	defer d.kill()
	golden := map[string]map[string]any{}
	for i := range hscens {
		r := runOne(d, srv, &hscens[i], mutByID("C0"), nil)
		if r.Drv != nil && r.Drv["ok"] == true {
			golden[hscens[i].ID] = r.Drv
		}
	}
	for _, t := range list {
		p := strings.Split(t, ":")
		sc, m := scenByID(p[0]), mutByID(p[1])
		if sc == nil || m == nil {
			return fmt.Errorf("unknown triple %s", t)
		}
		var sigs []string
		var last RunRec
		for range n {
			last = runOne(d, srv, sc, m, golden[sc.ID])
			sigs = append(sigs, sigOf(last))
		}
		same := true
		for _, s := range sigs {
			if s != sigs[0] {
				same = false
			}
		}
		fmt.Printf("%-7s %-4s %-5s repeats=%d identical=%v sig=%s outcome=%s ms=%d peakMB=%d\n", sdk, p[0], p[1], n, same, sigs[0], last.Outcome, last.Ms, last.PeakMB)
		for _, v := range last.Viol {
			fmt.Printf("        %s %s %s\n", v.Oracle, v.Sev, v.Detail)
		}
	}
	return nil
}

func loadResults(dir string) ([]RunRec, error) {
	f, err := os.Open(filepath.Join(dir, "results.jsonl")) // #nosec G304 -- operator path
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var out []RunRec
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var r RunRec
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// hostileDiff lists the (scenario, mutation, oracle) violations of a run that the baseline run lacks, per SDK.
func hostileDiff(args []string) error {
	fs := flag.NewFlagSet("hostile diff", flag.ExitOnError)
	a := fs.String("base", "", "baseline results dir")
	bdir := fs.String("run", "", "run results dir")
	sdk := fs.String("sdk", "", "SDK to compare")
	_ = fs.Parse(args)
	ra, err := loadResults(*a)
	if err != nil {
		return err
	}
	rb, err := loadResults(*bdir)
	if err != nil {
		return err
	}
	key := func(r RunRec, v Viol) string { return r.Scen + "|" + r.Mut + "|" + v.Oracle }
	base := map[string]bool{}
	for _, r := range ra {
		if r.SDK == *sdk {
			for _, v := range r.Viol {
				base[key(r, v)] = true
			}
		}
	}
	n := 0
	for _, r := range rb {
		if r.SDK != *sdk {
			continue
		}
		for _, v := range r.Viol {
			if !base[key(r, v)] {
				n++
				fmt.Printf("NEW %s %s %s %s: %s\n", r.SDK, r.Scen, r.Mut, v.Oracle, v.Detail)
			}
		}
	}
	// and the reverse: violations that vanished
	cur := map[string]bool{}
	for _, r := range rb {
		if r.SDK == *sdk {
			for _, v := range r.Viol {
				cur[key(r, v)] = true
			}
		}
	}
	gone := 0
	for _, r := range ra {
		if r.SDK != *sdk {
			continue
		}
		for _, v := range r.Viol {
			if !cur[key(r, v)] {
				gone++
				fmt.Printf("GONE %s %s %s %s\n", r.SDK, r.Scen, r.Mut, v.Oracle)
			}
		}
	}
	fmt.Printf("new=%d gone=%d\n", n, gone)
	return nil
}
