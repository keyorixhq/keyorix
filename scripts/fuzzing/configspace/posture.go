package configspace

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// postureFuncs evaluates the independent insecure-posture predicates of model.yaml on
// an effective configuration. They deliberately do not consult
// config.InsecureSettingsRegistry: the registry is the code under test (I3 asks
// whether the code's own notion of "insecure" is complete).
var postureFuncs = map[string]func(*config.Config) bool{
	"P01": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			if l.inst.Enabled && !l.inst.TLS.Enabled && !isLoopbackHost(l.inst.BindHost()) {
				return true
			}
		}
		return false
	},
	"P02": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			if l.inst.Enabled && !l.inst.TLS.Enabled {
				return true
			}
		}
		return false
	},
	"P03": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			if !l.inst.Enabled {
				continue
			}
			if tok, err := l.inst.ResolveMetricsToken(); err != nil || tok == "" {
				return true
			}
		}
		return false
	},
	"P04": func(c *config.Config) bool { return !c.Storage.Encryption.Enabled },
	"P05": func(c *config.Config) bool { return c.Security.LoginLockout.Disabled },
	"P06": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			if l.inst.Enabled && (!l.inst.RateLimit.Enabled || l.inst.RateLimit.RequestsPerSecond <= 0) {
				return true
			}
		}
		return false
	},
	"P07": func(c *config.Config) bool { return !c.Security.RequireMFA },
	"P08": func(c *config.Config) bool {
		return !c.Security.EnableFilePermissionCheck || c.Security.AllowUnsafeFilePermissions
	},
	"P09": func(c *config.Config) bool { return c.Session.GetAbsoluteTTL() == 0 },
	"P10": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			for _, p := range l.inst.TrustedProxies {
				if pf, err := netip.ParsePrefix(p); err == nil && pf.Bits() == 0 {
					return true
				}
			}
		}
		return false
	},
	"P11": func(c *config.Config) bool {
		return (c.Server.HTTP.Enabled && c.Server.HTTP.SwaggerEnabled) || (c.Server.GRPC.Enabled && c.Server.GRPC.ReflectionEnabled)
	},
	"P12": func(c *config.Config) bool {
		s := c.Audit.SIEM
		lo := strings.ToLower(s.Endpoint)
		plain := strings.HasPrefix(lo, "http://") && !isLoopbackHost(hostOfOrigin(lo))
		return s.Enabled && (s.InsecureSkipVerify || plain)
	},
	"P13": func(c *config.Config) bool { return c.Security.RecoverAdmin.KeylessMode },
	"P14": func(c *config.Config) bool {
		kp := c.Storage.Encryption.KeyProvider
		if kp.AllowWeakerFallback {
			return true
		}
		for _, f := range kp.Fallbacks {
			if f.AllowWeakerFallback {
				return true
			}
		}
		return false
	},
	"P15": func(c *config.Config) bool {
		st := c.Storage.Database.EffectiveAuditDurability(c.Storage.Type)
		return st.Level == config.AuditDurabilityStandard || c.Storage.Database.InsecureAuditSkipReads || c.AuditCheckpoints.Disabled
	},
	"P16": func(c *config.Config) bool {
		for _, o := range c.Server.HTTP.AllowedOrigins {
			lo := strings.ToLower(o)
			if strings.HasPrefix(lo, "http://") && !isLoopbackHost(hostOfOrigin(lo)) {
				return true
			}
		}
		return false
	},
	"P17": func(c *config.Config) bool {
		if c.Storage.Type != "postgres" && c.Storage.Type != "postgresql" {
			return false
		}
		mode, err := config.EffectiveDatabaseSSLMode(&c.Storage.Database)
		if err != nil {
			return false
		}
		host := c.Storage.Database.Host
		if host == "" {
			host = "unknown-from-dsn"
		}
		return (mode == "disable" || mode == "allow" || mode == "prefer") && !isLoopbackHost(host)
	},
	"P18": func(c *config.Config) bool {
		for _, l := range listeners(c) {
			if !l.inst.Enabled {
				continue
			}
			suites, err := l.inst.TLS.ResolveCipherSuites(nil)
			if err != nil {
				continue
			}
			for _, s := range suites {
				for _, bad := range tls.InsecureCipherSuites() {
					if s == bad.ID {
						return true
					}
				}
			}
		}
		return false
	},
}

type namedListener struct {
	name string
	inst config.ServerInstanceConfig
}

func listeners(c *config.Config) []namedListener {
	return []namedListener{{"http", c.Server.HTTP}, {"grpc", c.Server.GRPC}}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hostOfOrigin(o string) string {
	o = strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")
	if i := strings.IndexAny(o, "/"); i >= 0 {
		o = o[:i]
	}
	if h, _, err := net.SplitHostPort(o); err == nil {
		return h
	}
	return o
}

// PostureHolds returns the ids of the posture predicates that hold on cfg.
func (m *Model) PostureHolds(cfg *config.Config) []string {
	var out []string
	for _, r := range m.Posture {
		if f := postureFuncs[r.ID]; f != nil && f(cfg) {
			out = append(out, r.ID)
		}
	}
	return out
}

// registryInEffect returns the names of the code's own insecure-settings registry
// entries in effect on cfg.
func registryInEffect(cfg *config.Config) (names []string, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = "registry InEffect panicked"
		}
	}()
	for _, s := range config.InsecureSettingsRegistry {
		if s.InEffect != nil && s.InEffect(cfg) {
			names = append(names, s.Name)
		}
	}
	return names, ""
}
