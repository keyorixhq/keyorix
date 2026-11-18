package osairgap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Result is what a jailed run reports back to the parent oracle. Every endpoint
// here is a REMOTE peer the child was seen talking to, or trying to; the parent
// runs Allowlist.Classify over them. CanaryHits are proxy/HTTP egress INTENTS
// (deterministic, with target); ProcPeers are direct dials caught by sampling
// /proc/net (best-effort). ContainmentErrs are the ENETUNREACH-class errors the
// child itself reported when a non-loopback dial was blocked by the netns.
type Result struct {
	LoUp             bool       `json:"lo_up"`
	CanaryAddr       string     `json:"canary_addr"`
	CanaryHits       []string   `json:"canary_hits"`  // "method host:port" or raw first line
	ProcPeers        []Endpoint `json:"proc_peers"`   // non-loopback remote peers sampled from /proc/net
	ProcSamples      int        `json:"proc_samples"` // how many times /proc/net was sampled
	TargetExit       int        `json:"target_exit"`
	TargetErr        string     `json:"target_err"`
	TargetStderrTail string     `json:"target_stderr_tail"`
	InitErr          string     `json:"init_err"`
}

// RunSpec configures one jailed run.
type RunSpec struct {
	// Argv is the target command run inside the netns. Argv[0] must be an
	// absolute path (the netns shares the mount namespace, so the host FS is
	// visible). To run the test binary itself as the target, use
	// os.Args[0]-style path with a helper role in Env.
	Argv []string
	// Env is extra environment for the target (on top of a sanitised base). The
	// jail ADDS proxy vars pointing at the canary; do not set them here.
	Env []string
	// DB, if set as "ip:port", is the one non-loopback endpoint the child is
	// allowed to reach; the sampler will not flag it. Informational for the
	// parent oracle (the parent classifies); the child records all peers.
	DB string
	// Timeout bounds the whole jailed run.
	Timeout time.Duration
	// SampleInterval is how often /proc/net is read. 0 => 5ms.
	SampleInterval time.Duration
}

// envRole/envSpec are how the parent hands the nsinit child its RunSpec through
// the /proc/self/exe re-exec (JSON on an env var — the child is a fresh process
// with no shared memory).
const (
	envRole = "AGP1_OSAIRGAP_ROLE"
	envSpec = "AGP1_OSAIRGAP_SPEC"
	roleNS  = "nsinit"
)

// Run executes spec inside a fresh network namespace and returns the Result.
// It re-execs the current test binary with roleNS so RunNSInit runs INSIDE the
// new netns (Go cannot usefully unshare(CLONE_NEWNET) in-process because the
// runtime is multi-threaded and only the calling thread would move). The caller
// must have arranged, in TestMain, for roleNS to dispatch to RunNSInit.
func Run(ctx context.Context, self string, spec RunSpec) (*Result, error) {
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, self, "-test.run=TestOsairgapNSInitDispatch") // #nosec G204 // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- self is the caller's own test binary (os.Args[0]); fuzz tooling, never shipped or fed attacker input
	cmd.Env = append(os.Environ(), envRole+"="+roleNS, envSpec+"="+string(specJSON))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET, // root with CAP_NET_ADMIN: net ns only
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// The nsinit child prints exactly one JSON Result line, prefixed, on stdout.
	res, perr := parseResultLine(stdout.Bytes())
	if perr != nil {
		return nil, fmt.Errorf("nsinit no result (run err=%v): stdout=%q stderr=%q", runErr, stdout.String(), tail(stderr.String(), 800))
	}
	return res, nil
}

const resultPrefix = "AGP1_RESULT: "

func parseResultLine(out []byte) (*Result, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, resultPrefix) {
			var r Result
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, resultPrefix)), &r); err != nil {
				return nil, err
			}
			return &r, nil
		}
	}
	return nil, errors.New("no result line")
}

// IsNSInit reports whether this process was re-exec'd as the netns-init child.
func IsNSInit() bool { return os.Getenv(envRole) == roleNS }

// RunNSInit is the body that runs INSIDE the new network namespace. It brings up
// loopback, starts the canary, points the target's proxy env at it, runs the
// target while sampling /proc/net, and prints the Result. It calls os.Exit.
func RunNSInit() {
	res := &Result{}
	defer func() {
		b, _ := json.Marshal(res)
		fmt.Println(resultPrefix + string(b))
		os.Exit(0)
	}()

	var spec RunSpec
	if err := json.Unmarshal([]byte(os.Getenv(envSpec)), &spec); err != nil {
		res.InitErr = "spec: " + err.Error()
		return
	}
	if spec.SampleInterval <= 0 {
		spec.SampleInterval = 5 * time.Millisecond
	}
	if spec.Timeout <= 0 {
		spec.Timeout = 30 * time.Second
	}

	if err := bringLoopbackUp(); err != nil {
		res.InitErr = "lo up: " + err.Error()
		// Keep going: some tests only need containment, not loopback.
	} else {
		res.LoUp = true
	}

	canary, err := startCanary()
	if err != nil {
		res.InitErr = "canary: " + err.Error()
		return
	}
	defer canary.Close()
	res.CanaryAddr = canary.addr

	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout)
	defer cancel()

	// Build target command. Proxy + resolver env point at the canary so any
	// proxy-respecting egress intent lands on loopback and is recorded.
	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...) // #nosec G204 // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- Argv is the parent test's own RunSpec, handed over by the re-exec above; the target is the program under test, run inside a network-less netns
	base := sanitisedEnv()
	proxy := "http://" + canary.addr
	base = append(base,
		"HTTP_PROXY="+proxy, "http_proxy="+proxy,
		"HTTPS_PROXY="+proxy, "https_proxy="+proxy,
		"ALL_PROXY="+proxy, "all_proxy="+proxy,
		"NO_PROXY=", "no_proxy=",
	)
	cmd.Env = append(base, spec.Env...)
	var tstderr bytes.Buffer
	cmd.Stderr = &tstderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		res.InitErr = "target start: " + err.Error()
		return
	}
	pid := cmd.Process.Pid

	// Sample /proc/<pid>/net/{tcp,tcp6,udp,udp6} until the target exits.
	peers := map[string]Endpoint{}
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		t := time.NewTicker(spec.SampleInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				res.ProcSamples++
				for _, p := range sampleProcNet(pid) {
					if !p.IP.IsLoopback() && !p.IP.IsUnspecified() {
						peers[p.String()] = p
					}
				}
				if cmd.ProcessState != nil {
					return
				}
			}
		}
	}()

	werr := cmd.Wait()
	cancel()
	<-sampleDone

	if cmd.ProcessState != nil {
		res.TargetExit = cmd.ProcessState.ExitCode()
	}
	if werr != nil {
		res.TargetErr = werr.Error()
	}
	res.TargetStderrTail = tail(tstderr.String(), 1500)
	for _, p := range peers {
		res.ProcPeers = append(res.ProcPeers, p)
	}
	res.CanaryHits = canary.hits()
}

// bringLoopbackUp sets IFF_UP on "lo" inside the current (new) netns via ioctl.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get flags: %w", err)
	}
	flags := ifr.Uint16()
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set flags: %w", err)
	}
	return nil
}

// sanitisedEnv drops the role/spec vars so the target does not think it is a
// nsinit child, and drops the Go test flags that would confuse a real binary.
func sanitisedEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, envRole+"=") || strings.HasPrefix(kv, envSpec+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// sampleProcNet reads the four /proc/<pid>/net files and returns every remote
// peer with a non-zero port (a zero remote port is a LISTEN socket, not egress).
func sampleProcNet(pid int) []Endpoint {
	var out []Endpoint
	for _, f := range []struct {
		name string
		v6   bool
	}{
		{"tcp", false}, {"tcp6", true}, {"udp", false}, {"udp6", true},
	} {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/net/" + f.name)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			_, rem, _, ok := parseProcNetLine(sc.Text(), f.v6)
			if !ok || rem.Port == 0 {
				continue
			}
			out = append(out, rem)
		}
	}
	return out
}
