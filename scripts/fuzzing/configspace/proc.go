package configspace

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProcResult is what the real keyorix-server binary did with a case.
type ProcResult struct {
	Exit       int // exit code, -1 when killed by a signal or still running
	Signal     string
	TimedOut   bool
	Started    bool     // every enabled listener logged a listening line
	Listening  []string // "http://127.0.0.1:1234" style, as logged
	Log        string
	Bodies     map[string]string // unauthenticated endpoint -> status + body
	Health     map[string]int
	ShutdownOK bool // exited 0 within the window after SIGTERM
	Graceful   bool // "All servers shut down gracefully" logged
	Admin      map[string]string
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var listenRE = regexp.MustCompile(`(HTTP server listening on (https?)://(\S+)|gRPC server listening on (\S+))`)

func procEnv(c *Case) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + c.Dir, "TMPDIR=" + c.Dir, "GOMAXPROCS=2", "LANG=C"}
	for k, v := range c.Env {
		env = append(env, k+"="+v)
	}
	return env
}

func niceCmd(ctx context.Context, bin string, c *Case, args ...string) *exec.Cmd {
	full := append([]string{"-n", "15", bin}, args...)
	cmd := exec.CommandContext(ctx, "nice", full...) // #nosec G204 -- fixed "nice" wrapper around the keyorix binary under test, whose path comes from the operator
	cmd.Dir = c.Dir
	cmd.Env = procEnv(c)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// RunProc starts the real server for the case, probes it, stops it with SIGTERM, then
// runs the offline admin commands, returning everything it saw. startWait bounds the
// wait for a start or a refusal; stopWait bounds the graceful shutdown.
func RunProc(bin string, c *Case, enabledHTTP, enabledGRPC bool, startWait, stopWait time.Duration) ProcResult {
	res := ProcResult{Exit: -1, Bodies: map[string]string{}, Health: map[string]int{}, Admin: map[string]string{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := niceCmd(ctx, bin, c, c.Args...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var buf lockedBuf
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		res.Log = "harness: start: " + err.Error()
		return res
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	want := 0
	if enabledHTTP {
		want++
	}
	if enabledGRPC {
		want++
	}
	deadline := time.Now().Add(startWait)
	settle := time.Now().Add(3 * time.Second) // no listeners: treat as started after 3 s
	exited := false
	var waitErr error
poll:
	for time.Now().Before(deadline) {
		select {
		case waitErr = <-done:
			exited = true
			break poll
		case <-time.After(100 * time.Millisecond):
		}
		log := buf.String()
		got := len(listenRE.FindAllString(log, -1))
		if want > 0 && got >= want {
			res.Started = true
			break
		}
		if want == 0 && time.Now().After(settle) && len(strings.TrimSpace(log)) > 0 {
			res.Started = true
			break
		}
	}
	if exited {
		res.Log = buf.String()
		res.Exit, res.Signal = exitInfo(waitErr)
		return res
	}
	if !res.Started {
		res.TimedOut = true
		_ = cmd.Process.Signal(syscall.SIGKILL)
		<-done //nolint:errcheck // killed on purpose: the wait error is the kill
		res.Log = buf.String()
		return res
	}
	// probe
	for _, m := range listenRE.FindAllStringSubmatch(buf.String(), -1) {
		if m[2] != "" {
			base := m[2] + "://" + m[3]
			base = strings.SplitN(base, " ", 2)[0]
			res.Listening = append(res.Listening, base)
			probeHTTP(c, base, &res)
		} else {
			res.Listening = append(res.Listening, "grpc://"+m[4])
		}
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case waitErr = <-done:
		res.Exit, res.Signal = exitInfo(waitErr)
		res.ShutdownOK = res.Exit == 0
	case <-time.After(stopWait):
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-done //nolint:errcheck // killed on purpose: the wait error is the kill
		res.TimedOut = true
	}
	res.Log = buf.String()
	res.Graceful = strings.Contains(res.Log, "All servers shut down gracefully")
	adminRun(bin, c, &res)
	return res
}

func exitInfo(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return -1, ws.Signal().String()
		}
		return ee.ExitCode(), ""
	}
	return -1, err.Error()
}

// pinnedRoots returns a pool of the certificates the case's server can present: every
// PEM certificate under <dir>/certs (the self-signed one admin init generated for the
// template, copied into the case) plus the configured server.http.tls.cert_file. The
// probe trusts only these, so it verifies the chain and the "localhost" name instead
// of skipping verification.
func pinnedRoots(c *Case) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	var files []string
	if m, err := filepath.Glob(filepath.Join(c.Dir, "certs", "*.crt")); err == nil {
		files = append(files, m...)
	}
	if v, ok := GetPath(c.Doc, "server.http.tls.cert_file"); ok {
		if s, _ := v.(string); s != "" {
			if !filepath.IsAbs(s) {
				s = filepath.Join(c.Dir, s)
			}
			files = append(files, s)
		}
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- certificate files inside the case's own private temp dir
		if err == nil && pool.AppendCertsFromPEM(b) {
			n++
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("no PEM certificate found under %s/certs or at the configured cert_file", c.Dir)
	}
	return pool, nil
}

// probeTLSConfig pins the case's own certificates for an https listener. ServerName is
// "localhost" because admin init always puts that name in the certificate and the logged
// listen address may be a wildcard (0.0.0.0, [::]) that no certificate names.
func probeTLSConfig(c *Case) (*tls.Config, error) {
	roots, err := pinnedRoots(c)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}, nil
}

// probeHTTP fetches the unauthenticated endpoints of one listener. For https it trusts
// only the case's pinned certificates (probeTLSConfig) with a TLS 1.2 floor.
//
// What it does NOT verify: that the server refuses TLS below 1.2 (the client never
// offers it), or which cipher suites the server permits; posture predicate P18 covers
// the configured floor and ciphers in process. A harness that cannot load any pinned
// certificate records "ERR harness: ..." and health 0 for that listener, so the failure
// surfaces as an I6 finding instead of being skipped silently.
func probeHTTP(c *Case, base string, res *ProcResult) {
	tr := &http.Transport{}
	if strings.HasPrefix(base, "https://") {
		tc, err := probeTLSConfig(c)
		if err != nil {
			res.Bodies[base+"/health"] = "ERR harness: " + err.Error()
			res.Health[base] = 0
			return
		}
		tr.TLSClientConfig = tc
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	for _, path := range []string{"/health", "/api/v1/system/info", "/metrics"} {
		resp, err := cl.Get(base + path)
		if err != nil {
			res.Bodies[base+path] = "ERR " + err.Error()
			if path == "/health" {
				res.Health[base] = 0
			}
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		res.Bodies[base+path] = strconv.Itoa(resp.StatusCode) + " " + string(b)
		if path == "/health" {
			res.Health[base] = resp.StatusCode
		}
	}
}

func adminRun(bin string, c *Case, res *ProcResult) {
	for _, a := range [][]string{{"admin", "validate", "--posture"}, {"admin", "diagnose"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		cmd := niceCmd(ctx, bin, c, append(a, "--config", c.Env["KEYORIX_CONFIG_PATH"])...)
		var buf lockedBuf
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		cancel()
		out := buf.String()
		if err != nil {
			out += fmt.Sprintf("\n[exit: %v]", err)
		}
		res.Admin[strings.Join(a, " ")] = out
	}
}
