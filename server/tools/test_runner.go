package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TestRunner provides utilities for running comprehensive tests
type TestRunner struct {
	verbose bool
	timeout time.Duration
}

// NewTestRunner creates a new test runner
func NewTestRunner(verbose bool, timeout time.Duration) *TestRunner {
	return &TestRunner{
		verbose: verbose,
		timeout: timeout,
	}
}

// RunAllTests runs all test suites
func (tr *TestRunner) RunAllTests() error {
	fmt.Println("🧪 Running Comprehensive Test Suite for HTTP/gRPC Server")
	fmt.Println("=" + strings.Repeat("=", 60))

	testSuites := []struct {
		name        string
		path        string
		description string
	}{
		{
			name:        "HTTP Handlers",
			path:        "./http/handlers",
			description: "Testing HTTP request handlers (secrets, RBAC, system, audit)",
		},
		{
			name:        "HTTP Integration",
			path:        "./http",
			description: "Testing complete HTTP server integration workflows",
		},
		{
			name:        "gRPC Services",
			path:        "./grpc/services",
			description: "Testing gRPC service implementations",
		},
		{
			name:        "Middleware",
			path:        "./middleware",
			description: "Testing authentication and authorization middleware",
		},
	}

	totalStart := time.Now()
	var failedSuites []string

	for i, suite := range testSuites {
		fmt.Printf("\n📋 Test Suite %d/%d: %s\n", i+1, len(testSuites), suite.name)
		fmt.Printf("📁 Path: %s\n", suite.path)
		fmt.Printf("📝 Description: %s\n", suite.description)
		fmt.Println(strings.Repeat("-", 60))

		if err := tr.runTestSuite(suite.path, suite.name); err != nil {
			fmt.Printf("❌ FAILED: %s\n", suite.name)
			fmt.Printf("   Error: %v\n", err)
			failedSuites = append(failedSuites, suite.name)
		} else {
			fmt.Printf("✅ PASSED: %s\n", suite.name)
		}
	}

	totalDuration := time.Since(totalStart)

	// Print summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("📊 TEST SUMMARY (Total time: %v)\n", totalDuration)
	fmt.Println(strings.Repeat("=", 60))

	if len(failedSuites) == 0 {
		fmt.Printf("🎉 ALL TESTS PASSED! (%d/%d test suites)\n", len(testSuites), len(testSuites))
		fmt.Println("✨ The HTTP and gRPC server implementation is working correctly!")
	} else {
		fmt.Printf("❌ %d/%d test suites FAILED:\n", len(failedSuites), len(testSuites))
		for _, suite := range failedSuites {
			fmt.Printf("   - %s\n", suite)
		}
		return fmt.Errorf("%d test suites failed", len(failedSuites))
	}

	return nil
}

// runTestSuite runs tests for a specific package
func (tr *TestRunner) runTestSuite(path, name string) error {
	// #129: path is hardcoded in the testSuites table today (RunAllTests), not
	// user-controlled — but this function's own exec.Command call had no
	// validateTestPath gate at all, unlike RunBenchmarks below. Applying it here
	// too closes the gap defense-in-depth, so a later refactor that parameterizes
	// path (e.g. from a CLI flag) doesn't silently reopen a command-argument
	// injection surface (a value containing another `go test` flag, or a package
	// path outside this tree).
	if err := validateTestPath(path); err != nil {
		return fmt.Errorf("invalid test path %q: %w", path, err)
	}

	start := time.Now()

	// Build the go test command
	args := []string{"test"}

	if tr.verbose {
		args = append(args, "-v")
	}

	args = append(args, "-timeout", tr.timeout.String())
	args = append(args, "-race")  // Enable race detection
	args = append(args, "-cover") // Enable coverage
	args = append(args, path)

	cmd := exec.Command("go", args...) // #nosec G204 -- path is validated by validateTestPath above // NOSONAR go:S4036
	cmd.Dir = "."                      // Run from server directory

	// Capture output
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if tr.verbose || err != nil {
		fmt.Printf("⏱️  Duration: %v\n", duration)
		fmt.Printf("🔧 Command: go %s\n", strings.Join(args, " "))
		if len(output) > 0 {
			fmt.Printf("📄 Output:\n%s\n", string(output))
		}
	}

	if err != nil {
		return fmt.Errorf("test suite failed: %w", err)
	}

	return nil
}

// validateTestPath validates that a test path is safe to use.
//
// #129: this used to check the "./"-prefix requirement on the ALREADY-CLEANED path
// (filepath.Clean("./http") == "http" — Clean always strips a leading "./"), so the
// check rejected every legitimate input unconditionally. It failed CLOSED (every real
// caller — RunBenchmarks — got "path must be relative", so nothing this guarded ever
// actually ran), which is why it went unnoticed rather than surfacing as a visible
// bug: the intended feature was silently broken, not exploitably open. Fixed by
// checking the "./" prefix on the RAW input before cleaning, and matching the allowed
// directories against the cleaned (dot-slash-stripped) form.
func validateTestPath(path string) error {
	// The "./" prefix requirement is checked on the raw path — see above.
	if !strings.HasPrefix(path, "./") {
		return fmt.Errorf("path must be relative and start with './'")
	}

	// Clean the path to prevent directory traversal (e.g. "./http/../../../etc").
	cleanPath := filepath.Clean(path)

	// Prevent directory traversal attacks: a cleaned path escaping the current
	// directory begins with "..".
	if cleanPath == ".." || strings.HasPrefix(cleanPath, "../") {
		return fmt.Errorf("path cannot contain '..' (directory traversal)")
	}

	// Only allow specific safe directories — exact match or a subdirectory of one.
	// cleanPath has no leading "./" (Clean strips it), so match without it too.
	allowedDirs := []string{"http", "grpc", "middleware", "validation", "services"}
	allowed := false
	for _, dir := range allowedDirs {
		if cleanPath == dir || strings.HasPrefix(cleanPath, dir+"/") {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("path not in allowed directories")
	}

	return nil
}

// RunBenchmarks runs benchmark tests
func (tr *TestRunner) RunBenchmarks() error {
	fmt.Println("🏃 Running Performance Benchmarks")
	fmt.Println("=" + strings.Repeat("=", 40))

	benchmarks := []struct {
		name string
		path string
	}{
		{"HTTP Handlers", "./http/handlers"},
		{"Middleware", "./middleware"},
		{"gRPC Services", "./grpc/services"},
	}

	for _, bench := range benchmarks {
		fmt.Printf("\n🏁 Benchmarking: %s\n", bench.name)
		fmt.Println(strings.Repeat("-", 30))

		// Validate and sanitize the path to prevent command injection
		if err := validateTestPath(bench.path); err != nil {
			fmt.Printf("❌ Invalid benchmark path %s: %v\n", bench.path, err)
			continue
		}

		// Use fixed command structure with validated paths
		args := []string{"test", "-bench=.", "-benchmem", bench.path}
		cmd := exec.Command("go", args...) // #nosec G204 -- Path is validated by validateTestPath function // NOSONAR go:S4036
		cmd.Dir = "."

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("❌ Benchmark failed: %v\n", err)
			continue
		}

		fmt.Printf("📊 Results:\n%s\n", string(output))
	}

	return nil
}

// RunCoverageReport generates a coverage report
func (tr *TestRunner) RunCoverageReport() error {
	fmt.Println("📈 Generating Coverage Report")
	fmt.Println("=" + strings.Repeat("=", 30))

	// Run tests with coverage
	cmd := exec.Command("go", "test", "-coverprofile=coverage.out", "./...") // NOSONAR go:S4036
	cmd.Dir = "."

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("coverage test failed: %w\nOutput: %s", err, string(output))
	}

	// Generate HTML coverage report
	cmd = exec.Command("go", "tool", "cover", "-html=coverage.out", "-o", "coverage.html") // NOSONAR go:S4036
	cmd.Dir = "."

	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️  Could not generate HTML coverage report: %v\n", err)
	} else {
		fmt.Println("✅ Coverage report generated: coverage.html")
	}

	// Show coverage summary
	cmd = exec.Command("go", "tool", "cover", "-func=coverage.out") // NOSONAR go:S4036
	cmd.Dir = "."

	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("⚠️  Could not generate coverage summary: %v\n", err)
	} else {
		fmt.Printf("📊 Coverage Summary:\n%s\n", string(output))
	}

	return nil
}

// run executes the requested command and returns the process exit code.
// It is separated from main so that tests can call it directly without
// triggering os.Exit, keeping main() as a thin wrapper.
func run(args []string) int {
	if len(args) < 2 {
		fmt.Println("Usage: go run test_runner.go [command]")
		fmt.Println("Commands:")
		fmt.Println("  all        - Run all tests")
		fmt.Println("  bench      - Run benchmarks")
		fmt.Println("  coverage   - Generate coverage report")
		fmt.Println("  help       - Show this help")
		return 1
	}

	command := args[1]
	runner := NewTestRunner(true, 5*time.Minute)

	switch command {
	case "all":
		if err := runner.RunAllTests(); err != nil {
			fmt.Printf("❌ Tests failed: %v\n", err)
			return 1
		}
	case "bench":
		if err := runner.RunBenchmarks(); err != nil {
			fmt.Printf("❌ Benchmarks failed: %v\n", err)
			return 1
		}
	case "coverage":
		if err := runner.RunCoverageReport(); err != nil {
			fmt.Printf("❌ Coverage report failed: %v\n", err)
			return 1
		}
	case "help":
		fmt.Println("HTTP/gRPC Server Test Runner")
		fmt.Println("============================")
		fmt.Println()
		fmt.Println("This tool runs comprehensive tests for the Keyorix HTTP and gRPC server implementation.")
		fmt.Println()
		fmt.Println("Available commands:")
		fmt.Println("  all        - Run all test suites (unit, integration, performance)")
		fmt.Println("  bench      - Run performance benchmarks")
		fmt.Println("  coverage   - Generate test coverage report")
		fmt.Println()
		fmt.Println("Test suites included:")
		fmt.Println("  - HTTP Handlers: Secret, RBAC, System, Audit endpoint tests")
		fmt.Println("  - HTTP Integration: End-to-end workflow tests")
		fmt.Println("  - gRPC Services: gRPC service implementation tests")
		fmt.Println("  - Middleware: Authentication and authorization tests")
		fmt.Println()
		fmt.Println("Example usage:")
		fmt.Println("  go run test_runner.go all")
		fmt.Println("  go run test_runner.go bench")
		fmt.Println("  go run test_runner.go coverage")
	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Use 'go run test_runner.go help' for available commands")
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args))
}
