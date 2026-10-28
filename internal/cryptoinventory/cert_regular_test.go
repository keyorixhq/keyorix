package cryptoinventory

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadWithin runs LoadCertificates and fails the test (instead of hanging it) when
// the call does not return in time. Cleanup opens the FIFO for writing so a reader
// stuck in open(2) is released and no goroutine outlives the test.
func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := LoadCertificates(path, 1)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		<-done
		t.Fatalf("LoadCertificates(%s) blocked: a configured certificate path must be opened non-blocking", filepath.Base(path))
		return nil
	}
}

// A mis-pointed cert_file / ssl_root_cert that is a FIFO must be refused at once,
// not hang the inventory (and the request serving it) in open(2).
func TestLoadCertificates_RefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "cert.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	err := loadWithin(t, fifo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

func TestLoadCertificates_RefusesSymlinkToFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "cert.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	link := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.Symlink(fifo, link))
	err := loadWithin(t, link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

func TestLoadCertificates_RefusesDirectory(t *testing.T) {
	err := loadWithin(t, t.TempDir())
	require.Error(t, err)
}

// A symlink to a regular file stays readable: a Kubernetes Secret volume exposes
// each key as a symlink into the kubelet's ..data directory.
func TestLoadCertificates_FollowsSymlinkToRegularFile(t *testing.T) {
	in, _ := fullInputs(t)
	real := in.TLS[0].CertFile
	link := filepath.Join(t.TempDir(), "tls-link.pem")
	require.NoError(t, os.Symlink(real, link))
	infos, err := LoadCertificates(link, 1)
	require.NoError(t, err)
	assert.Len(t, infos, 1)
}
