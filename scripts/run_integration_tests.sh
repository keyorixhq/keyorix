#!/bin/bash

# Script to run comprehensive integration tests for secret sharing functionality
# This script runs all integration tests and generates a comprehensive report

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="10m"
COVERAGE_THRESHOLD=80
REPORT_DIR="test-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}🚀 Starting Secret Sharing Integration Tests${NC}"
echo "=================================================="
echo "Timestamp: $(date)"
echo "Test Timeout: $TEST_TIMEOUT"
echo "Coverage Threshold: $COVERAGE_THRESHOLD%"
echo "Report Directory: $REPORT_DIR"
echo ""

# Function to print section headers
print_section() {
    local msg="$1"
    echo -e "\n${BLUE}📋 ${msg}${NC}"
    echo "----------------------------------------"
}

# Function to print success messages
print_success() {
    local msg="$1"
    echo -e "${GREEN}✅ ${msg}${NC}"
}

# Function to print warning messages
print_warning() {
    local msg="$1"
    echo -e "${YELLOW}⚠️  ${msg}${NC}"
}

# Function to print error messages
print_error() {
    local msg="$1"
    echo -e "${RED}❌ ${msg}${NC}"
}

# Function to run tests with coverage
run_tests_with_coverage() {
    local test_path="$1"
    local test_name="$2"
    local output_file="$REPORT_DIR/${test_name}_${TIMESTAMP}.out"
    local coverage_file="$REPORT_DIR/${test_name}_coverage_${TIMESTAMP}.out"
    
    print_section "Running $test_name Tests"
    
    if go test -v -timeout="$TEST_TIMEOUT" -coverprofile="$coverage_file" "$test_path" > "$output_file" 2>&1; then
        print_success "$test_name tests passed"
        
        # Generate coverage report
        if [[ -f "$coverage_file" ]]; then
            coverage_percent=$(go tool cover -func="$coverage_file" | grep total | awk '{print $3}' | sed 's/%//')
            echo "Coverage: ${coverage_percent}%"
            
            if (( $(echo "$coverage_percent >= $COVERAGE_THRESHOLD" | bc -l) )); then
                print_success "Coverage threshold met: ${coverage_percent}% >= ${COVERAGE_THRESHOLD}%"
            else
                print_warning "Coverage below threshold: ${coverage_percent}% < ${COVERAGE_THRESHOLD}%"
            fi
        fi
        
        return 0
    else
        print_error "$test_name tests failed"
        echo "Check $output_file for details"
        return 1
    fi
}

# Function to run benchmarks
run_benchmarks() {
    local test_path="$1"
    local benchmark_name="$2"
    local output_file="$REPORT_DIR/${benchmark_name}_benchmark_${TIMESTAMP}.out"
    
    print_section "Running $benchmark_name Benchmarks"
    
    if go test -v -bench=. -benchmem -timeout="$TEST_TIMEOUT" "$test_path" > "$output_file" 2>&1; then
        print_success "$benchmark_name benchmarks completed"
        echo "Results saved to $output_file"
        return 0
    else
        print_error "$benchmark_name benchmarks failed"
        echo "Check $output_file for details"
        return 1
    fi
}

# Initialize test results tracking
declare -a test_results
declare -a test_names

# Test 1: Core Integration Tests
test_names+=("Core Integration")
if run_tests_with_coverage "./internal/core" "core_integration"; then
    test_results+=(0)
else
    test_results+=(1)
fi

# Test 2: HTTP API Integration Tests
test_names+=("HTTP API Integration")
if run_tests_with_coverage "./server/http" "http_integration"; then
    test_results+=(0)
else
    test_results+=(1)
fi

# Test 3: gRPC Integration Tests
test_names+=("gRPC Integration")
if run_tests_with_coverage "./server/grpc" "grpc_integration"; then
    test_results+=(0)
else
    test_results+=(1)
fi

# Test 4: CLI Integration Tests
test_names+=("CLI Integration")
if run_tests_with_coverage "./internal/cli/share" "cli_integration"; then
    test_results+=(0)
else
    test_results+=(1)
fi

# Test 5: Comprehensive Integration Test Suite
test_names+=("Comprehensive Suite")
if run_tests_with_coverage "./test/integration" "comprehensive_suite"; then
    test_results+=(0)
else
    test_results+=(1)
fi

# Run benchmarks
print_section "Performance Benchmarks"
run_benchmarks "./test/integration" "sharing_performance"

# Test 6: Storage Layer Tests (if sharing-specific tests exist)
if [[ -d "./internal/storage/local" ]]; then
    test_names+=("Storage Layer")
    if run_tests_with_coverage "./internal/storage/local" "storage_integration"; then
        test_results+=(0)
    else
        test_results+=(1)
    fi
fi

# Test 7: Encryption Integration Tests (if sharing-specific tests exist)
if [[ -d "./internal/encryption" ]]; then
    test_names+=("Encryption Integration")
    if run_tests_with_coverage "./internal/encryption" "encryption_integration"; then
        test_results+=(0)
    else
        test_results+=(1)
    fi
fi

# Generate comprehensive coverage report
print_section "Generating Comprehensive Coverage Report"
coverage_files=$(find "$REPORT_DIR" -name "*coverage*.out" -type f)
if [[ -n "$coverage_files" ]]; then
    combined_coverage="$REPORT_DIR/combined_coverage_${TIMESTAMP}.out"
    
    # Combine all coverage files
    echo "mode: set" > "$combined_coverage"
    for file in $coverage_files; do
        tail -n +2 "$file" >> "$combined_coverage"
    done
    
    # Generate HTML coverage report
    html_coverage="$REPORT_DIR/coverage_report_${TIMESTAMP}.html"
    go tool cover -html="$combined_coverage" -o "$html_coverage"
    
    # Calculate overall coverage
    overall_coverage=$(go tool cover -func="$combined_coverage" | grep total | awk '{print $3}' | sed 's/%//')
    
    print_success "Combined coverage report generated: $html_coverage"
    echo "Overall coverage: ${overall_coverage}%"
    
    if (( $(echo "$overall_coverage >= $COVERAGE_THRESHOLD" | bc -l) )); then
        print_success "Overall coverage threshold met: ${overall_coverage}% >= ${COVERAGE_THRESHOLD}%"
    else
        print_warning "Overall coverage below threshold: ${overall_coverage}% < ${COVERAGE_THRESHOLD}%"
    fi
fi

# Generate test summary report
print_section "Test Summary Report"
summary_file="$REPORT_DIR/test_summary_${TIMESTAMP}.txt"

{
    echo "Secret Sharing Integration Test Summary"
    echo "======================================"
    echo "Timestamp: $(date)"
    echo "Test Timeout: $TEST_TIMEOUT"
    echo "Coverage Threshold: $COVERAGE_THRESHOLD%"
    echo ""
    
    passed_count=0
    failed_count=0
    
    for i in "${!test_names[@]}"; do
        test_name="${test_names[$i]}"
        result="${test_results[$i]}"
        
        if [[ "$result" -eq 0 ]]; then
            echo "✅ $test_name: PASSED"
            ((passed_count++))
        else
            echo "❌ $test_name: FAILED"
            ((failed_count++))
        fi
    done
    
    echo ""
    echo "Summary:"
    echo "--------"
    echo "Total Tests: $((passed_count + failed_count))"
    echo "Passed: $passed_count"
    echo "Failed: $failed_count"
    echo "Success Rate: $(( passed_count * 100 / (passed_count + failed_count) ))%"
    
    if [[ -n "$overall_coverage" ]]; then
        echo "Overall Coverage: ${overall_coverage}%"
    fi
    
} > "$summary_file"

# Display summary
cat "$summary_file"

# Final result
echo ""
echo "=================================================="
if [[ "$failed_count" -eq 0 ]]; then
    print_success "🎉 All integration tests passed!"
    echo "Reports available in: $REPORT_DIR"
    exit 0
else
    print_error "💥 $failed_count test suite(s) failed"
    echo "Check individual test reports in: $REPORT_DIR"
    exit 1
fi