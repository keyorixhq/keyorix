package contracttest

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// specPath is resolved relative to this source file's own location (not the
// process's working directory, which varies with how `go test` is invoked)
// so it holds regardless of which package's test binary links this one in.
var specPath = func() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("contracttest: runtime.Caller(0) failed -- cannot locate openapi.yaml")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "openapi.yaml")
}()

var (
	specOnce sync.Once
	spec     *openapi3.T
	router   routers.Router
	specErr  error
)

// loadSpec parses and validates openapi.yaml and builds the operation router,
// once per test binary. Every exported entry point calls this first.
func loadSpec() {
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile(specPath)
		if err != nil {
			specErr = fmt.Errorf("contracttest: loading %s: %w", specPath, err)
			return
		}
		if err := doc.Validate(loader.Context); err != nil {
			specErr = fmt.Errorf("contracttest: %s failed OpenAPI validation: %w", specPath, err)
			return
		}
		r, err := gorillamux.NewRouter(doc)
		if err != nil {
			specErr = fmt.Errorf("contracttest: building operation router from %s: %w", specPath, err)
			return
		}
		spec = doc
		router = r
	})
}
