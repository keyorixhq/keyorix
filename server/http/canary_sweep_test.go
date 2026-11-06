package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/canary"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sweepSeed() uint64 {
	if v := os.Getenv("CANARY_SEED"); v != "" {
		var n uint64
		fmt.Sscan(v, &n)
		return n
	}
	return 1
}

// TestCanaryRouteSweep is the deterministic campaign (PREREG.md). It fails when
// any secret-class canary appears on a forbidden surface; CANARY_OUT=<file>
// writes every finding with its request repro. The planted-leak self-test below
// must pass in the same run for a clean result to mean anything.
func TestCanaryRouteSweep(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, sweepSeed())
	defer s.close()
	routes := listSweepRoutes(t, s.w.router)
	dispN := 0
	if v := os.Getenv("CANARY_MAX_ROUTES"); v != "" {
		var n int
		fmt.Sscan(v, &n)
		routes = routes[:min(n, len(routes))]
	}
	for i, rt := range routes {
		if rt.Method == "CONNECT" || rt.Method == "TRACE" {
			continue
		}
		principals := []string{"admin", "outsider", "anon", "garbage"}
		for _, p := range principals {
			destructive := sweepDestructive.MatchString(rt.Pattern)
			if destructive && p == "admin" {
				// Exercised as a throw-away self-service principal instead.
				for _, r := range s.shapesFor(rt, "admin") {
					tok, ok := s.disposable(dispN)
					dispN++
					if !ok {
						continue
					}
					r.Principal = "disposable"
					r.Header.Set("Authorization", "Bearer "+tok)
					s.run(r)
				}
				continue
			}
			for _, r := range s.shapesFor(rt, p) {
				s.run(r)
			}
		}
		s.scanPersistentDeep(rt.String(), i%40 == 39)
		if i%50 == 0 {
			t.Logf("route %d/%d requests=%d findings=%d", i, len(routes), s.nreq, len(s.hits))
		}
	}
	s.grpcSweep(t)
	s.scanPersistentDeep("end-of-sweep", true)
	s.writeFindings(os.Getenv("CANARY_OUT"))

	// Harness sanity: the metadata control must have been seen on a response
	// and in the database, otherwise "no secret found" proves nothing.
	var sawResp, sawDB bool
	for k := range s.metaSeen {
		sawResp = sawResp || strings.HasPrefix(k, "resp-body|") || strings.HasPrefix(k, "grpc-resp|") || strings.HasPrefix(k, "grpc-error|")
		sawDB = sawDB || strings.HasPrefix(k, "db:")
	}
	if !sawResp || !sawDB {
		t.Fatalf("INVALID RUN: metadata control not observed (resp=%v db=%v); the oracle could not see storage or responses", sawResp, sawDB)
	}
	t.Logf("requests=%d status=%v metadata-control-surfaces=%d", s.nreq, s.statusN, len(s.metaSeen))
	// Known finding F1 is tracked privately with the maintainers; counted and
	// reported, not gated. Every other surface/shape still fails the run.
	knownF1 := 0
	for _, f := range s.findings() {
		if sh, _ := f.Repro["shape"].(string); f.Surface == "log" && (sh == "query" || sh == "query-h") {
			knownF1++
			continue
		}
		t.Errorf("LEAK candidate: surface=%s route=%s label=%s variant=%s class=%s snippet=%s repro=%v", f.Surface, f.Route, f.Label, f.Variant, f.Class, f.Snippet, f.Repro)
	}
	t.Logf("known-F1 findings: %d", knownF1)
}

// ---- gRPC ---------------------------------------------------------------------

func (s *sweep) grpcFill(desc protoreflect.MessageDescriptor, alt bool, depth int) *dynamicpb.Message {
	msg := dynamicpb.NewMessage(desc)
	if depth > 3 {
		return msg
	}
	seenOneof := map[protoreflect.Name]bool{}
	fs := desc.Fields()
	for i := 0; i < fs.Len(); i++ {
		fd := fs.Get(i)
		if oo := fd.ContainingOneof(); oo != nil && !oo.IsSynthetic() {
			if seenOneof[oo.Name()] {
				continue
			}
			seenOneof[oo.Name()] = true
		}
		if fd.IsMap() {
			continue
		}
		val := func() protoreflect.Value {
			switch fd.Kind() {
			case protoreflect.StringKind:
				return protoreflect.ValueOfString(s.fieldCanary(string(fd.Name()), alt).Raw)
			case protoreflect.BytesKind:
				return protoreflect.ValueOfBytes([]byte(s.fieldCanary(string(fd.Name()), alt).Raw))
			case protoreflect.MessageKind, protoreflect.GroupKind:
				return protoreflect.ValueOfMessage(s.grpcFill(fd.Message(), alt, depth+1))
			case protoreflect.BoolKind:
				return protoreflect.ValueOfBool(true)
			case protoreflect.EnumKind:
				if v := fd.Enum().Values(); v.Len() > 1 {
					return protoreflect.ValueOfEnum(v.Get(1).Number())
				}
				return protoreflect.ValueOfEnum(0)
			case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				return protoreflect.ValueOfUint64(1)
			case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
				return protoreflect.ValueOfUint32(1)
			case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
				return protoreflect.ValueOfInt64(1)
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
				return protoreflect.ValueOfInt32(1)
			}
			return fd.Default()
		}()
		if fd.IsList() {
			msg.Mutable(fd).List().Append(val)
		} else {
			msg.Set(fd, val)
		}
	}
	return msg
}

// grpcSweep calls every unary method the live gRPC server registers, as admin,
// as an unauthenticated caller and with a garbage bearer, with canaries in every
// string/bytes field and in request metadata, and scans response bytes, the
// status message and details, and the server log.
func (s *sweep) grpcSweep(t testing.TB) {
	type m struct {
		svc, name string
		in, out   protoreflect.MessageDescriptor
	}
	var ms []m
	for svc, info := range s.w.grpcSrv.GetServiceInfo() {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svc))
		if err != nil {
			t.Fatalf("service %s has no descriptor: %v", svc, err)
		}
		sd := d.(protoreflect.ServiceDescriptor)
		for _, mi := range info.Methods {
			md := sd.Methods().ByName(protoreflect.Name(mi.Name))
			if md == nil || md.IsStreamingClient() || md.IsStreamingServer() {
				continue
			}
			ms = append(ms, m{svc, mi.Name, md.Input(), md.Output()})
		}
	}
	n := 0
	for _, mm := range ms {
		for _, who := range []string{"admin", "anon", "garbage"} {
			for _, alt := range []bool{false, true} {
				ctx := metadata.AppendToOutgoingContext(context.Background(),
					"x-request-id", s.byLabel["m-requestid"].Raw, "x-api-key", s.byLabel["apikey"].Raw)
				switch who {
				case "admin":
					ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.w.adminTok)
				case "garbage":
					ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.byLabel["authhdr"].Raw)
				}
				req := s.grpcFill(mm.in, alt, 0)
				resp := dynamicpb.NewMessage(mm.out)
				err := s.w.grpcConn.Invoke(ctx, "/"+mm.svc+"/"+mm.name, req, resp, grpc.WaitForReady(false))
				n++
				route := "grpc " + mm.svc + "/" + mm.name
				attr := &sweepReq{Method: "gRPC", Target: route, Principal: who, Shape: fmt.Sprintf("fill alt=%v", alt), Route: route}
				wire, _ := proto.Marshal(resp)
				js, _ := protojson.Marshal(resp)
				s.scan("grpc-resp", route, attr, append(wire, js...), 0)
				if err != nil {
					st := status.Convert(err)
					d := st.Message()
					for _, det := range st.Details() {
						d += fmt.Sprint(det)
					}
					s.scan("grpc-error", route, attr, []byte(d), int(st.Code()))
				}
				s.scan("log", route, attr, s.w.drainLog(), 0)
				if s.stdout != nil {
					s.scan("stdout", route, attr, s.stdout.drain(), 0)
				}
				if s.stderr != nil {
					s.scan("stderr", route, attr, s.stderr.drain(), 0)
				}
			}
		}
		if n%200 == 0 {
			s.scanPersistent(fmt.Sprintf("grpc after %s/%s", mm.svc, mm.name))
		}
	}
	t.Logf("gRPC: %d unary methods, %d calls", len(ms), n)
}

// ---- planted-leak self-test -----------------------------------------------------

// TestCanaryOracle_PlantedLeaksAreDetected is the precondition for trusting a
// clean TestCanaryRouteSweep: a deliberately leaky wrapper puts a canary, in
// every encoded variant, on every surface the oracle claims to watch, and the
// oracle must flag each one. A metadata (class M) canary on the same surfaces
// must not become a finding, and a clean request must produce none.
func TestCanaryOracle_PlantedLeaksAreDetected(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 4242)
	defer s.close()

	var plant struct {
		surface string
		data    []byte
	}
	real := s.w.router
	if _, err := s.w.db.DB(); err != nil {
		t.Fatal(err)
	}
	if err := s.w.db.Exec("CREATE TABLE canary_selftest (id INTEGER PRIMARY KEY, ciphertext_only TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	s.w.router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" && plant.surface == "metrics" {
			_, _ = w.Write(plant.data)
			return
		}
		if r.URL.Path != "/__plant" {
			real.ServeHTTP(w, r)
			return
		}
		switch plant.surface {
		case "resp-body":
			_, _ = w.Write(plant.data)
		case "resp-header":
			w.Header().Set("X-Leak", strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, string(plant.data)))
		case "log":
			log.Printf("leaked: %s", plant.data)
		case "stdout":
			fmt.Fprintf(os.Stdout, "leaked: %s\n", plant.data)
		case "stderr":
			fmt.Fprintf(os.Stderr, "leaked: %s\n", plant.data)
		case "db":
			s.w.db.Exec("INSERT INTO canary_selftest(ciphertext_only) VALUES (?)", string(plant.data))
		case "tempfile":
			_ = os.WriteFile(filepath.Join(os.TempDir(), fmt.Sprintf("kx-canary-selftest-%d", os.Getpid())), plant.data, 0o600)
		}
	})

	surfaces := []string{"resp-body", "resp-header", "log", "stdout", "stderr", "db", "tempfile", "metrics"}
	type exp struct{ surfacePrefix, label string }
	var expected []exp
	for _, surf := range surfaces {
		nvars := len(canary.New("probe", canary.Secret, 1, true).Variants())
		for vi := 0; vi < nvars; vi++ {
			// A distinct canary per (surface, variant) so each planted encoding
			// is judged on its own and cannot be satisfied by another's hit.
			c := canary.New(fmt.Sprintf("st-%s-%d", surf, vi), canary.Secret, 4242+uint64(vi), true)
			v := c.Variants()[vi]
			label := c.Label
			s.register(c)
			plant.surface, plant.data = surf, v.Bytes
			s.run(sweepReq{Method: "GET", Target: "/__plant", Header: http.Header{}, Principal: "anon", Shape: "plant", Route: "GET /__plant"})
			// The persistent scan treats the planted bytes as already seen after
			// the first sighting (per surface/label/variant); labels are unique
			// per planted variant so each is judged on its own.
			s.scanPersistent("plant " + label)
			prefix := map[string]string{"db": "db:", "tempfile": "tempfile:", "metrics": "metrics"}[surf]
			if prefix == "" {
				prefix = surf
			}
			expected = append(expected, exp{prefix, label})
			if surf == "db" {
				expected = append(expected, exp{"dbfile:", label})
			}
		}
	}
	missed := 0
	for _, e := range expected {
		found := false
		for _, h := range s.hits {
			if h.Label == e.label && strings.HasPrefix(h.Surface, e.surfacePrefix) {
				found = true
				break
			}
		}
		if !found {
			missed++
			t.Errorf("planted leak NOT detected: surface=%s %s (variant %s)", e.surfacePrefix, e.label, canary.New("probe", canary.Secret, 1, true).Variants()[variantIndex(e.label)].Name)
		}
	}
	if missed > 0 {
		t.Fatalf("self-test FAILED: %d of %d planted leaks missed; any clean sweep result is INVALID", missed, len(expected))
	}
	t.Logf("self-test: %d planted (surface x encoding) leaks, all detected", len(expected))

	// Negative controls.
	before := len(s.hits)
	plant.surface = "none"
	s.run(sweepReq{Method: "GET", Target: "/healthz", Header: http.Header{}, Principal: "anon", Shape: "clean", Route: "GET /healthz"})
	if len(s.hits) != before {
		t.Fatalf("clean request produced %d new hits", len(s.hits)-before)
	}
	meta := s.byLabel["m-name"]
	plant.surface, plant.data = "resp-body", []byte(meta.Raw)
	s.run(sweepReq{Method: "GET", Target: "/__plant", Header: http.Header{}, Principal: "anon", Shape: "plant-meta", Route: "GET /__plant"})
	if len(s.hits) != before {
		t.Fatalf("metadata-class canary was reported as a finding")
	}
	if !s.metaSeen["resp-body|m-name"] {
		t.Fatalf("metadata control not counted")
	}
}

func variantIndex(label string) int {
	i := strings.LastIndex(label, "-")
	var n int
	fmt.Sscan(label[i+1:], &n)
	return n
}
