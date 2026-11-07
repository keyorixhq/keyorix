package configspace

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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
	cmd := exec.CommandContext(ctx, "nice", full...)
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
		<-done
		res.Log = buf.String()
		return res
	}
	// probe
	for _, m := range listenRE.FindAllStringSubmatch(buf.String(), -1) {
		if m[2] != "" {
			base := m[2] + "://" + m[3]
			base = strings.SplitN(base, " ", 2)[0]
			res.Listening = append(res.Listening, base)
			probeHTTP(base, &res)
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
		<-done
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

func probeHTTP(base string, res *ProcResult) {
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- local probe of a self-signed test server
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
		resp.Body.Close()
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
