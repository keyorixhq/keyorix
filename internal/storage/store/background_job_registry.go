package store

import (
	"context"
	"runtime/debug"
	"slices"
	"sync"
)

// liveJobs is every backgroundJob whose goroutine has not returned yet, with
// the stack that started it. Only Close stops a job early, so a job still in
// here after its owner is done means that owner never called Close: its
// goroutine keeps running (and logging through the global logger) into
// whatever runs next in the process. Tests assert it is empty
// (LiveBackgroundJobs).
var liveJobs = struct {
	sync.Mutex
	m map[*backgroundJob]string
}{m: map[*backgroundJob]string{}}

// newBackgroundJob registers a job and returns the context its goroutine runs
// under. The goroutine must `defer job.exit()` as its first statement.
func newBackgroundJob() (context.Context, *backgroundJob) {
	ctx, cancel := context.WithCancel(context.Background())
	job := &backgroundJob{cancel: cancel, done: make(chan struct{})}
	liveJobs.Lock()
	liveJobs.m[job] = string(debug.Stack())
	liveJobs.Unlock()
	return ctx, job
}

// exit deregisters the job, then closes done: once Close (or
// WaitAuditListIndexBuild) has seen done closed, LiveBackgroundJobs no longer
// lists the job.
func (job *backgroundJob) exit() {
	liveJobs.Lock()
	delete(liveJobs.m, job)
	liveJobs.Unlock()
	close(job.done)
}

// LiveBackgroundJobs returns the start stack of every background job
// (StartAuditListIndexBuild, StartRolePermissionsGenerationIntegrityCheck)
// whose goroutine is still running, sorted. A test package's TestMain calls it
// after m.Run: anything listed was started by a storage some test never
// closed. It covers only goroutines started through newBackgroundJob, not the
// audit flusher or other goroutines of this package.
func LiveBackgroundJobs() []string {
	liveJobs.Lock()
	defer liveJobs.Unlock()
	out := make([]string, 0, len(liveJobs.m))
	for _, stack := range liveJobs.m {
		out = append(out, stack)
	}
	slices.Sort(out)
	return out
}
