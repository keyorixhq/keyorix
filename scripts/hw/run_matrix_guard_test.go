//go:build unix

package hw_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the REAL run-matrix.sh against a fake CPU temperature sensor
// (HWMON_PKG) to pin its live abort contract. They pin the REVIEW-4551-DEEP-1
// M1 finding: the thermal brake (`sleep 60; continue`) skipped the abort, disk
// and SMART checks, so at CPU > CPU_PAUSE_C a cell never aborted and the matrix
// moved on to the next, heavier cell. Only the idle baseline cell runs
// (MATRIX_STORAGES=""), so no clone or go build is started.

// runMatrix runs run-matrix.sh with the sensor reading tempMilliC and the given
// extra environment, and returns its combined output, run.log and exit code.
// The script runs in its own process group, which is killed when the test ends,
// so a sampler it started cannot outlive the test.
func runMatrix(t *testing.T, tempMilliC string, extra ...string) (string, string, int) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("run-matrix.sh pre-flight needs go in PATH")
	}
	dir := t.TempDir()
	sensor := filepath.Join(dir, "temp")
	if err := os.WriteFile(sensor, []byte(tempMilliC+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := filepath.Join(dir, "results")
	hdd := filepath.Join(dir, "hdd")
	tmpfs := filepath.Join(dir, "tmpfs")
	for _, d := range []string{hdd, tmpfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "run-matrix.sh", results)
	cmd.Env = append(os.Environ(),
		"HWMON_PKG="+sensor,
		"HDD_ROOT="+hdd,
		"TMPFS_ROOT="+tmpfs,
		"DISKS=NA",
		"MATRIX_STORAGES=",
		"LOAD_S=2",
		"COOLDOWN_S=1",
		"GUARD_INTERVAL_S=1",
		"GOPROXY=off",
	)
	cmd.Env = append(cmd.Env, extra...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("run-matrix.sh did not finish within 45s (guard stuck?); output:\n%s", out)
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	runLog, _ := os.ReadFile(filepath.Join(results, "run.log"))
	return string(out), string(runLog), code
}

// CPU above both CPU_ABORT_C (90) and CPU_PAUSE_C (92): the abort must win and
// stop the matrix with exit 42, never fall through to "done".
func TestRunMatrix_CPUAbortWinsOverThermalBrake(t *testing.T) {
	out, runLog, code := runMatrix(t, "95000", "CPU_ABORT_HOLD_S=0")
	if code != 42 {
		t.Fatalf("exit code = %d, want 42 (abort); output:\n%s", code, out)
	}
	if !strings.Contains(runLog, "CELL cell00-idle-N0 ABORTED — stopping matrix") {
		t.Fatalf("run.log has no ABORTED line for the baseline cell:\n%s", runLog)
	}
	if strings.Contains(runLog, "cell00-idle-N0: done") {
		t.Fatalf("aborted cell also reported done:\n%s", runLog)
	}
}

// CPU above CPU_PAUSE_C but the abort hold is not reached: the brake pauses the
// workload, the guard keeps its normal cadence (no 60 s stall) and the cell
// completes.
func TestRunMatrix_ThermalBrakeWithoutAbortCompletes(t *testing.T) {
	out, runLog, code := runMatrix(t, "95000", "CPU_ABORT_HOLD_S=3600")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, out)
	}
	if !strings.Contains(runLog, "thermal brake: CPU 95C > 92C — workload paused") {
		t.Fatalf("run.log has no thermal brake line:\n%s", runLog)
	}
	if strings.Contains(runLog, "ABORT") {
		t.Fatalf("brake below the abort hold must not abort:\n%s", runLog)
	}
	if !strings.Contains(runLog, "MATRIX COMPLETE") {
		t.Fatalf("run.log has no MATRIX COMPLETE line:\n%s", runLog)
	}
}

// Green baseline: a cool CPU neither brakes nor aborts.
func TestRunMatrix_CoolCPUCompletes(t *testing.T) {
	out, runLog, code := runMatrix(t, "50000", "CPU_ABORT_HOLD_S=0")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, out)
	}
	for _, bad := range []string{"ABORT", "thermal brake"} {
		if strings.Contains(runLog, bad) {
			t.Fatalf("cool run logged %q:\n%s", bad, runLog)
		}
	}
	if !strings.Contains(runLog, "cell00-idle-N0: done") {
		t.Fatalf("baseline cell did not complete:\n%s", runLog)
	}
}
