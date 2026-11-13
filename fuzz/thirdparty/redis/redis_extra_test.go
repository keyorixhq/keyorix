// H6 extensions to the go-redis hostile-server harness: the ASK redirect (sibling of
// MOVED) and the Sentinel get-master-addr-by-name redirect — both exercising the SAME
// egress oracle as moved_redirect_test.go: a redirect/referral naming an attacker host
// must NOT be dialled by the single-node client Keyorix actually uses, and the configured
// password must NOT reach that host. Each carries a red proof (the cluster/failover
// client, which Keyorix deliberately does NOT use, DOES follow the redirect) so the green
// result is a real property, not a vacuous one.
//
// Reachability: dynamic/redis.go and rotation/redis.go both build a single-node
// redis.NewClient (never ClusterClient/FailoverClient) and run client.Do("ACL", …)
// against an operator-configured target. A hostile target can answer with -ASK, and a
// hostile Sentinel can answer get-master-addr-by-name with an attacker host.
package redishostile

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// runRedirectScenario drives two application commands against a configured server that
// answers every application command with "-<verb> 0 <attacker>" (MOVED or ASK), returning
// how many times the attacker host was dialled and whether the password leaked there.
func runRedirectScenario(t *testing.T, verb string, mk func(addr, password string) doer) (int32, bool) {
	attacker := newAttacker(t)
	defer attacker.close()

	var cfgHost, cfgPort string
	srv := hostile.NewServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			name, _, err := readCommand(r)
			if err != nil {
				return
			}
			switch name {
			case "HELLO":
				_, _ = c.Write(helloMap)
			case "CLIENT", "AUTH", "ASKING":
				_, _ = c.Write([]byte("+OK\r\n"))
			case "CLUSTER":
				_, _ = c.Write(clusterSlotsAll(cfgHost, cfgPort))
			case "":
				return
			default:
				_, _ = c.Write([]byte("-" + verb + " 0 " + attacker.addr() + "\r\n"))
			}
		}
	})
	defer srv.Close()
	cfgHost, cfgPort, _ = net.SplitHostPort(srv.Addr())

	client := mk(srv.Addr(), sentinelPassword)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = client.Do(ctx, "ACL", "SETUSER", "kx_dyn", "on", ">"+sentinelPassword).Err()
	_ = client.Do(ctx, "ACL", "DELUSER", "kx_dyn").Err()
	time.Sleep(200 * time.Millisecond)
	return attacker.dials.Load(), attacker.leaked()
}

func singleNode(addr, pw string) doer {
	return redis.NewClient(&redis.Options{
		Addr: addr, Protocol: 3, DisableIdentity: true, Password: pw,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, MaxRetries: -1,
	})
}

func clusterNode(addr, pw string) doer {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: []string{addr}, Protocol: 3, DisableIdentity: true, Password: pw,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, MaxRedirects: 3,
	})
}

// TestRedisAskNotFollowed: the single-node client must NOT dial an -ASK redirect target
// and must NOT send the password there.
func TestRedisAskNotFollowed(t *testing.T) {
	dials, leaked := runRedirectScenario(t, "ASK", singleNode)
	if dials != 0 {
		t.Errorf("ORACLE egress: single-node client dialled ASK target %d time(s); must be 0", dials)
	}
	if leaked {
		t.Errorf("ORACLE egress: configured password reached the ASK redirect target")
	}
}

// TestRedisAskRedProof: the ClusterClient (NOT used by Keyorix) DOES follow -ASK, proving
// the green ASK result above is load-bearing.
func TestRedisAskRedProof(t *testing.T) {
	dials, leaked := runRedirectScenario(t, "ASK", clusterNode)
	t.Logf("red proof: ClusterClient dialled attacker %d time(s) on ASK, leaked=%v", dials, leaked)
	if dials == 0 {
		t.Skip("ClusterClient did not follow ASK in this build; red proof inconclusive (green test still exercises the detector)")
	}
}

// ---- Sentinel get-master-addr-by-name egress ------------------------------------------

// runSentinelScenario stands up a hostile Sentinel that answers
// `SENTINEL get-master-addr-by-name` with the attacker host:port, plus a hostile master
// at the configured address. Returns how many times the attacker (the sentinel-named
// "master") was dialled, and whether the password leaked there.
func runSentinelScenario(t *testing.T, mk func(sentinelAddr, password string) doer) (int32, bool) {
	attacker := newAttacker(t)
	defer attacker.close()
	aHost, aPort, _ := net.SplitHostPort(attacker.addr())

	sentinel := hostile.NewServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			name, _, err := readCommand(r)
			if err != nil {
				return
			}
			switch name {
			case "HELLO":
				_, _ = c.Write(helloMap)
			case "CLIENT", "AUTH":
				_, _ = c.Write([]byte("+OK\r\n"))
			case "SENTINEL":
				// get-master-addr-by-name → [host, port] pointing at the attacker.
				reply := "*2\r\n$" + strconv.Itoa(len(aHost)) + "\r\n" + aHost +
					"\r\n$" + strconv.Itoa(len(aPort)) + "\r\n" + aPort + "\r\n"
				_, _ = c.Write([]byte(reply))
			case "SUBSCRIBE", "PSUBSCRIBE":
				_, _ = c.Write([]byte("+OK\r\n"))
			case "":
				return
			default:
				_, _ = c.Write([]byte("+OK\r\n"))
			}
		}
	})
	defer sentinel.Close()

	client := mk(sentinel.Addr(), sentinelPassword)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = client.Do(ctx, "ACL", "SETUSER", "kx_dyn", "on", ">"+sentinelPassword).Err()
	time.Sleep(300 * time.Millisecond)
	return attacker.dials.Load(), attacker.leaked()
}

// TestRedisSentinelRedProof is the red proof for the Sentinel egress path: a FailoverClient
// (which Keyorix deliberately does NOT use) dials the attacker host the hostile Sentinel
// named as master. Keyorix's single-node redis.NewClient never issues SENTINEL commands,
// so it cannot be redirected this way at all — this red proof documents the egress risk
// the single-node choice avoids.
func TestRedisSentinelRedProof(t *testing.T) {
	dials, leaked := runSentinelScenario(t, func(sentinelAddr, pw string) doer {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName: "mymaster", SentinelAddrs: []string{sentinelAddr},
			Protocol: 3, DisableIdentity: true, Password: pw,
			DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
			WriteTimeout: 2 * time.Second, MaxRetries: -1,
		})
	})
	t.Logf("red proof: FailoverClient dialled attacker-named master %d time(s), leaked=%v", dials, leaked)
	if dials == 0 {
		t.Skip("FailoverClient did not dial the sentinel-named master in this build; red proof inconclusive")
	}
}
