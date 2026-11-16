// Self-contained fuzz module for the differential-fuzzing kit (diffkit) and its
// instances. It is a SEPARATE Go module on purpose: the kit must not drag
// Keyorix's dependency graph into the modules it is copied into, and the
// reference implementations the instances compare against (lestrrat-go/jwx,
// russellhaering/gosaml2, …) must never enter the production root go.mod.
// Mirror the operator/ and cli/ submodule convention: build and test this
// module with GOWORK=off (it is intentionally absent from the root go.work).
module github.com/keyorixhq/keyorix/fuzzkit

go 1.27

require github.com/golang-jwt/jwt/v5 v5.3.1
