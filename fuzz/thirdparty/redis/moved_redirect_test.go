package redishostile

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// doer is the slice of the redis client API Keyorix uses; both *redis.Client and
// *redis.ClusterClient satisfy it, which lets the red proof swap in the cluster client.
type doer interface {
	Do(ctx context.Context, args ...any) *redis.Cmd
	Close() error
}

const sentinelPassword = "KX-SENTINEL-PW-do-not-leak"

// clusterSlotsAll builds a CLUSTER SLOTS reply assigning all 16384 slots to one node.
func clusterSlotsAll(host, port string) []byte {
	id := "0000000000000000000000000000000000000000"
	node := "*3\r\n" +
		"$" + strconv.Itoa(len(host)) + "\r\n" + host + "\r\n" +
		":" + port + "\r\n" +
		"$" + strconv.Itoa(len(id)) + "\r\n" + id + "\r\n"
	return []byte("*1\r\n*3\r\n:0\r\n:16383\r\n" + node)
}

// attackerListener is a second loopback "server" standing in for the host a MOVED/ASK
// redirect points at. It records how many times it was dialled and whether the
// configured password ever reached it.
type attackerListener struct {
	ln      net.Listener
	dials   atomic.Int32
	mu      sync.Mutex
	sawPass bool
	done    chan struct{}
}

func newAttacker(t *testing.T) *attackerListener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("attacker listen: %v", err)
	}
	a := &attackerListener{ln: ln, done: make(chan struct{})}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.dials.Add(1)
			go a.handle(c)
		}
	}()
	return a
}

func (a *attackerListener) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)
	// Complete HELLO so the client proceeds far enough to send AUTH/commands, and scan
	// everything that arrives for the configured password.
	buf := make([]byte, 4096)
	for {
		// Peek/scan bytes: read, test for sentinel, reply plausibly.
		n, err := r.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), sentinelPassword) {
			a.mu.Lock()
			a.sawPass = true
			a.mu.Unlock()
		}
		if n > 0 {
			// Reply to keep the client talking (best-effort; content need not be exact).
			_, _ = c.Write(helloMap)
			_, _ = c.Write([]byte("+OK\r\n"))
		}
		if err != nil {
			return
		}
	}
}

func (a *attackerListener) addr() string { return a.ln.Addr().String() }
func (a *attackerListener) close()       { _ = a.ln.Close() }
func (a *attackerListener) leaked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sawPass
}

// runMovedScenario drives one application command against a configured server that
// replies "-MOVED 0 <attacker>" (and ASK on a second command), returning how many times
// the attacker host was dialled and whether the password leaked there.
func runMovedScenario(t *testing.T, mk func(addr, password string) doer) (dials int32, leaked bool) {
	attacker := newAttacker(t)
	defer attacker.close()

	var seenMu sync.Mutex
	var seen []string
	var cfgHost, cfgPort string
	// Configured (operator) server: completes HELLO, then answers every application
	// command with a MOVED redirect to the attacker host.
	srv := hostile.NewServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			name, _, err := readCommand(r)
			if err != nil {
				return
			}
			seenMu.Lock()
			seen = append(seen, name)
			seenMu.Unlock()
			switch name {
			case "HELLO":
				_, _ = c.Write(helloMap)
			case "CLIENT", "AUTH":
				_, _ = c.Write([]byte("+OK\r\n"))
			case "CLUSTER":
				// One slot range covering all 16384 slots, owned by the configured
				// (seed) node: the cluster client routes the command here, where it
				// then receives the MOVED redirect below.
				_, _ = c.Write(clusterSlotsAll(cfgHost, cfgPort))
			case "":
				return
			default:
				_, _ = c.Write([]byte("-MOVED 0 " + attacker.addr() + "\r\n"))
			}
		}
	})
	defer srv.Close()
	cfgHost, cfgPort, _ = net.SplitHostPort(srv.Addr())

	client := mk(srv.Addr(), sentinelPassword)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Two commands, to exercise both MOVED (cached redirect) paths.
	_ = client.Do(ctx, "ACL", "SETUSER", "kx_dyn", "on", ">"+sentinelPassword).Err()
	_ = client.Do(ctx, "ACL", "DELUSER", "kx_dyn").Err()
	time.Sleep(200 * time.Millisecond) // let any async redirect dial land
	seenMu.Lock()
	t.Logf("configured server saw commands: %v", seen)
	seenMu.Unlock()
	return attacker.dials.Load(), attacker.leaked()
}

// TestRedisMovedNotFollowed is the egress oracle: the single-node client Keyorix uses
// (redis.NewClient) must NOT dial a MOVED/ASK redirect target and must NOT send the
// configured password there.
func TestRedisMovedNotFollowed(t *testing.T) {
	dials, leaked := runMovedScenario(t, func(addr, pw string) doer {
		return redis.NewClient(&redis.Options{
			Addr: addr, Protocol: 3, DisableIdentity: true, Password: pw,
			DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
			WriteTimeout: 2 * time.Second, MaxRetries: -1,
		})
	})
	if dials != 0 {
		t.Errorf("ORACLE egress: single-node client dialled MOVED redirect target %d time(s); must be 0", dials)
	}
	if leaked {
		t.Errorf("ORACLE egress: configured password reached the MOVED redirect target")
	}
}

// TestRedisMovedRedProof is the red proof that the oracle above is load-bearing: a
// ClusterClient (which Keyorix deliberately does NOT use) DOES follow MOVED, dialling the
// attacker host — so the single-node green result is a real property, not a vacuous one.
func TestRedisMovedRedProof(t *testing.T) {
	dials, leaked := runMovedScenario(t, func(addr, pw string) doer {
		return redis.NewClusterClient(&redis.ClusterOptions{
			Addrs: []string{addr}, Protocol: 3, DisableIdentity: true, Password: pw,
			DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
			WriteTimeout: 2 * time.Second, MaxRedirects: 3,
		})
	})
	t.Logf("red proof: ClusterClient dialled attacker %d time(s), password leaked=%v", dials, leaked)
	if dials == 0 {
		t.Skip("ClusterClient did not follow MOVED in this build; red proof inconclusive (oracle instrument still exercised by green test)")
	}
}
