package dsn

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// RevokeTarget describes, as one comparable string, what a dynamic-secret
// backend's Revoke reaches with adminDSN: two DSNs of the same backend whose
// RevokeTarget is equal revoke on the same server. ok is false when the target
// cannot be read; a caller deciding "same target" must treat that as different
// (fail closed).
//
// Per backend:
//   - postgres, mysql, mongodb, redis: the set of host:port the driver dials,
//     lower-cased, with the driver's default port filled in where none is
//     written (5432, 3306, 27017, 6379), so "host=X" equals "postgres://…@X:5432".
//     The ParseDSNHosts union is part of the target too, so a host any other
//     reading of the string names also has to match. A DSN with no host (a
//     postgres service= or socket default, a bare mysql "@tcp/") is not readable.
//     The database is not part of it: DROP ROLE / DROP USER / dropUser (in the
//     fixed auth database) / ACL DELUSER act server-wide.
//   - kubernetes: api_server (scheme, host, port with the scheme's default, path;
//     empty is in-cluster), namespace and revocable, the three fields Revoke uses.
//   - aws-sts, gcp, azure: Revoke is a no-op (internal/dynamic), so every DSN
//     of the backend has the same target. Remove the backend here when its
//     Revoke starts to reach something.
//
// Other backends are not readable.
//
// Not covered: the driver's environment defaults (PGHOST, PGPORT) are not read;
// they are the same for the old and the new DSN of one server process.
func RevokeTarget(backendType, adminDSN string) (string, bool) {
	var addrs []string
	var ok bool
	switch backendType {
	case "aws-sts", "gcp", "azure":
		return backendType + ": revoke is a no-op", true
	case "kubernetes":
		return kubernetesRevokeTarget(adminDSN)
	case "postgres", "postgresql":
		addrs, ok = postgresRevokeAddrs(adminDSN)
	case "mysql":
		addrs, ok = mysqlRevokeAddrs(adminDSN)
	case "mongodb":
		addrs, ok = mongoRevokeAddrs(adminDSN)
	case "redis":
		addrs, ok = redisRevokeAddrs(adminDSN)
	}
	hosts := ParseDSNHosts(adminDSN)
	if !ok || len(addrs) == 0 || len(hosts) == 0 {
		return "", false
	}
	return backendType + " addrs=" + canonicalSet(addrs) + " hosts=" + canonicalSet(hosts), true
}

// canonicalSet is items lower-cased, sorted, deduplicated and comma-joined.
func canonicalSet(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = strings.ToLower(s)
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ",")
}

// hostPort joins host and a decimal port; ok is false for a port that is not one.
func hostPort(host, port string) (string, bool) {
	n, err := strconv.Atoi(port)
	if host == "" || err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), true
}

// pairHostsPorts pairs comma-separated host and port lists the way pgconn does:
// no port is the default, one port applies to every host, otherwise one per host.
func pairHostsPorts(hostField, portField, defPort string) ([]string, bool) {
	hosts := strings.Split(hostField, ",")
	ports := []string{defPort}
	if portField != "" {
		ports = strings.Split(portField, ",")
	}
	if len(ports) != 1 && len(ports) != len(hosts) {
		return nil, false
	}
	var out []string
	for i, h := range hosts {
		p := ports[0]
		if len(ports) > 1 {
			p = ports[i]
		}
		a, ok := hostPort(strings.TrimSpace(h), strings.TrimSpace(p))
		if !ok {
			return nil, false
		}
		out = append(out, a)
	}
	return out, true
}

// postgresRevokeAddrs reads a postgres DSN the way pgconn.ParseConfig does: a
// postgres:// or postgresql:// URL (netloc hosts and ports, ?host= / ?port=
// override them), otherwise keyword/value (the last host= and port= win).
// hostaddr= values are kept as entries of their own, so changing one is a change.
func postgresRevokeAddrs(s string) ([]string, bool) {
	var hostField, portField string
	var extra []string
	if strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://") {
		hosts, ports, query, ok := pgURLNetloc(s)
		if !ok {
			return nil, false
		}
		hostField, portField = strings.Join(hosts, ","), strings.Join(ports, ",")
		for pair := range strings.SplitSeq(query, "&") {
			k, v, _ := strings.Cut(pair, "=")
			switch k, v = percentDecodeLenient(k), percentDecodeLenient(v); k {
			case "host":
				hostField = v
			case "port":
				portField = v
			case "hostaddr":
				extra = append(extra, "hostaddr="+v)
			}
		}
	} else {
		pairs, ok := keywordValuePairsStrict(s)
		if !ok {
			return nil, false
		}
		for _, kv := range pairs {
			switch kv[0] {
			case "host":
				hostField = kv[1]
			case "port":
				portField = kv[1]
			case "hostaddr":
				extra = append(extra, "hostaddr="+kv[1])
			}
		}
	}
	if hostField == "" {
		return nil, false
	}
	addrs, ok := pairHostsPorts(hostField, portField, "5432")
	return append(addrs, extra...), ok
}

// pgURLNetloc splits a postgres URL's netloc the way pgconn's parse_url.go does
// (userinfo ends at the first '@' before any '/'; '[' runs to ']', otherwise a
// host runs to ':', '/', '?' or ','). It returns the decoded hosts, their ports
// (none when no host wrote one) and the query. A list where only some hosts
// write a port is not read: pgconn's pairing of such a list is not one this
// comparison can mirror safely.
func pgURLNetloc(s string) (hosts, ports []string, query string, ok bool) {
	_, p, _ := strings.Cut(s, "://")
	if i := strings.IndexAny(p, "@/"); i >= 0 && p[i] == '@' {
		p = p[i+1:]
	}
	withPort := 0
	for {
		var h string
		if strings.HasPrefix(p, "[") {
			rb := strings.IndexByte(p, ']')
			if rb < 0 {
				return nil, nil, "", false
			}
			h, p = p[1:rb], p[rb+1:]
		} else {
			i := strings.IndexAny(p, ":/?,")
			if i < 0 {
				i = len(p)
			}
			h, p = percentDecodeLenient(p[:i]), p[i:]
		}
		port := ""
		if strings.HasPrefix(p, ":") {
			i := strings.IndexAny(p, "/?,")
			if i < 0 {
				i = len(p)
			}
			port, p = percentDecodeLenient(p[1:i]), p[i:]
			withPort++
		}
		if h != "" {
			hosts = append(hosts, h)
		}
		ports = append(ports, port)
		if !strings.HasPrefix(p, ",") {
			break
		}
		p = p[1:]
	}
	switch withPort {
	case 0:
		ports = nil
	case len(ports):
	default:
		return nil, nil, "", false
	}
	_, query, _ = strings.Cut(p, "?")
	return hosts, ports, query, true
}

// mysqlRevokeAddrs reads the address the way go-sql-driver/mysql's ParseDSN
// does (last '/', last '@' before it, then net(addr)); a tcp address without a
// port gets 3306, a unix socket is kept as its path.
func mysqlRevokeAddrs(s string) ([]string, bool) {
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		return nil, false
	}
	netAddr := s[strings.LastIndexByte(s[:i], '@')+1 : i]
	k := strings.IndexByte(netAddr, '(')
	if k < 0 || !strings.HasSuffix(netAddr, ")") {
		return nil, false
	}
	network, addr := netAddr[:k], netAddr[k+1:len(netAddr)-1]
	switch {
	case addr == "":
		return nil, false
	case network == "unix":
		return []string{"unix:" + addr}, true
	case network != "tcp" && network != "tcp4" && network != "tcp6":
		return nil, false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = strings.Trim(addr, "[]"), "3306"
	}
	a, ok := hostPort(host, port)
	return []string{network + ":" + a}, ok
}

// mongoRevokeAddrs reads a mongodb URI the way the driver's connstring does:
// the hosts run to the first '/', userinfo ends at the last '@' in them, each
// comma-separated host is unescaped and gets 27017 without a port. A
// mongodb+srv URI names one SRV host and no port.
func mongoRevokeAddrs(s string) ([]string, bool) {
	scheme, rest, _ := strings.Cut(s, "://")
	if scheme != "mongodb" && scheme != "mongodb+srv" {
		return nil, false
	}
	hosts, _, slash := strings.Cut(rest, "/")
	if !slash && strings.Contains(rest, "?") {
		return nil, false // the driver refuses a query without a '/' before it
	}
	if at := strings.LastIndexByte(hosts, '@'); at >= 0 {
		hosts = hosts[at+1:]
	}
	var out []string
	for h := range strings.SplitSeq(hosts, ",") {
		h, err := url.QueryUnescape(h)
		if err != nil || h == "" {
			return nil, false
		}
		if scheme == "mongodb+srv" {
			if strings.Contains(hosts, ",") || strings.Contains(h, ":") {
				return nil, false
			}
			out = append(out, "srv:"+h)
			continue
		}
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			host, port = strings.Trim(h, "[]"), "27017"
		}
		a, ok := hostPort(host, port)
		if !ok {
			return nil, false
		}
		out = append(out, a)
	}
	return out, true
}

// redisRevokeAddrs reads a redis:// or rediss:// URL as go-redis's ParseURL
// does; no port is 6379. A URL with no host (go-redis then dials localhost) is
// not read.
func redisRevokeAddrs(s string) ([]string, bool) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Hostname() == "" {
		return nil, false
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	a, ok := hostPort(u.Hostname(), port)
	return []string{a}, ok
}

// kubernetesRevokeTarget is the kubernetes backend's revoke target: Revoke
// parses the same JSON with encoding/json (internal/dynamic k8sConfig), deletes
// the lease's bound Secret in namespace through api_server, and does nothing
// when revocable is false.
func kubernetesRevokeTarget(s string) (string, bool) {
	var cfg struct {
		APIServer string `json:"api_server"`
		Namespace string `json:"namespace"`
		Revocable bool   `json:"revocable"`
	}
	if err := json.Unmarshal([]byte(s), &cfg); err != nil {
		return "", false
	}
	api := "in-cluster"
	if raw := strings.TrimSpace(cfg.APIServer); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		scheme, port := strings.ToLower(u.Scheme), u.Port()
		if port == "" {
			switch scheme {
			case "https":
				port = "443"
			case "http":
				port = "80"
			default:
				return "", false
			}
		}
		a, ok := hostPort(strings.ToLower(u.Hostname()), port)
		if !ok {
			return "", false
		}
		api = scheme + "://" + a + strings.TrimRight(u.EscapedPath(), "/")
	}
	return fmt.Sprintf("kubernetes api_server=%s namespace=%q revocable=%t", api, cfg.Namespace, cfg.Revocable), true
}
