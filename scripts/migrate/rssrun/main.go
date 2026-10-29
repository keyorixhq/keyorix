//go:build ignore

// rssrun runs one command and records its peak resident set size and wall time
// (SCALE-OPS-1). It stands in for `/usr/bin/time -l`, which cannot run inside the
// macOS sandbox ("sysctl kern.clockrate: Operation not permitted") and is not
// available with the same flags on Linux. Like scripts/migrate/migratecheck it is a
// fixture tool, not part of any shipped binary (the //go:build ignore tag).
//
//	rssrun --stats FILE --log FILE [--kill TERM|KILL --when PATTERN [--after-ms N]] -- cmd args...
//
// The command's stdout and stderr go to --log. FILE receives one JSON line:
// {"exit":N,"signal":"","wall_s":1.23,"maxrss_kb":12345,"killed":false}. Peak RSS is
// the kernel's ru_maxrss for the command and its waited-for children (bytes on
// macOS, kilobytes on Linux; normalised to KB here). With --kill, rssrun polls the
// log and sends the signal to the command (its own PID, so the harness never uses
// the shared `kill`) as soon as PATTERN appears in it, optionally --after-ms later.
// The exit status is the command's, or 99 when it ended by the injected signal.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func main() {
	stats := flag.String("stats", "", "file for the JSON result line")
	logPath := flag.String("log", "", "file for the command's stdout+stderr")
	killSig := flag.String("kill", "", "TERM or KILL: signal to send when --when appears in the log")
	when := flag.String("when", "", "log substring that triggers --kill")
	afterMS := flag.Int("after-ms", 0, "delay between the pattern and the signal")
	flag.Parse()
	if *stats == "" || *logPath == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: rssrun --stats FILE --log FILE [--kill TERM|KILL --when PATTERN [--after-ms N]] -- cmd args...")
		os.Exit(2)
	}
	var sig syscall.Signal
	switch *killSig {
	case "":
	case "TERM":
		sig = syscall.SIGTERM
	case "KILL":
		sig = syscall.SIGKILL
	default:
		fmt.Fprintln(os.Stderr, "rssrun: --kill must be TERM or KILL")
		os.Exit(2)
	}
	if sig != 0 && *when == "" {
		fmt.Fprintln(os.Stderr, "rssrun: --kill needs --when")
		os.Exit(2)
	}
	logf, err := os.Create(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rssrun: %v\n", err)
		os.Exit(2)
	}
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Stdout, cmd.Stderr = logf, logf
	start := time.Now()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "rssrun: start: %v\n", err)
		os.Exit(2)
	}
	done := make(chan struct{})
	var killed bool
	if sig != 0 {
		go func() {
			needle := []byte(*when)
			for {
				select {
				case <-done:
					return
				case <-time.After(10 * time.Millisecond):
				}
				if data, err := os.ReadFile(*logPath); err == nil && bytes.Contains(data, needle) {
					time.Sleep(time.Duration(*afterMS) * time.Millisecond)
					killed = true
					_ = cmd.Process.Signal(sig)
					return
				}
			}
		}()
	}
	werr := cmd.Wait()
	close(done)
	wall := time.Since(start)
	res := map[string]any{"wall_s": float64(wall.Milliseconds()) / 1000, "killed": killed, "exit": 0, "signal": ""}
	if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		kb := int64(ru.Maxrss)
		if runtime.GOOS == "darwin" {
			kb /= 1024
		}
		res["maxrss_kb"] = kb
	}
	exit := 0
	if werr != nil {
		exit = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res["signal"] = ws.Signal().String()
			exit = 99
		}
	}
	res["exit"] = exit
	line, _ := json.Marshal(res)
	if err := os.WriteFile(*stats, append(line, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "rssrun: %v\n", err)
		os.Exit(2)
	}
	os.Exit(exit)
}
