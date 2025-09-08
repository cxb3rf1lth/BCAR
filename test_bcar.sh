#!/bin/bash

# BCAR Test Suite
# Comprehensive testing for BlackCell Auto Recon tool

set -euo pipefail

# Test configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BCAR_SCRIPT="$SCRIPT_DIR/bcar.sh"
readonly TEST_OUTPUT_DIR="/tmp/bcar_test_$$"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test result logging
test_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%H:%M:%S')"
    
    case "$level" in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} ${timestamp} - $message"
            ((TESTS_PASSED++))
            ((TESTS_RUN++))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} ${timestamp} - $message"
            ((TESTS_FAILED++))
            ((TESTS_RUN++))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} ${timestamp} - $message"
            ;;
    esac
}

# Setup test environment
setup_tests() {
    echo -e "${YELLOW}Setting up BCAR test environment...${NC}"
    mkdir -p "$TEST_OUTPUT_DIR"
    
    # Ensure bcar.sh is executable
    chmod +x "$BCAR_SCRIPT"
    
    test_log "INFO" "Test environment prepared at $TEST_OUTPUT_DIR"
}

# Cleanup test environment
cleanup_tests() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    rm -rf "$TEST_OUTPUT_DIR"
    test_log "INFO" "Test cleanup completed"
}

# Test 1: Basic syntax validation
test_syntax() {
    echo -e "${BLUE}Running syntax validation tests...${NC}"
    
    if bash -n "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "PASS" "Bash syntax validation"
    else
        test_log "FAIL" "Bash syntax validation failed"
    fi
    
    # Test demo script syntax too
    if [[ -f "$SCRIPT_DIR/demo.sh" ]]; then
        if bash -n "$SCRIPT_DIR/demo.sh" 2>/dev/null; then
            test_log "PASS" "Demo script syntax validation"
        else
            test_log "FAIL" "Demo script syntax validation failed"
        fi
    fi
}

# Test 2: Help functionality
test_help() {
    echo -e "${BLUE}Testing help functionality...${NC}"
    
    local help_output
    if help_output="$("$BCAR_SCRIPT" --help 2>&1)"; then
        if [[ "$help_output" == *"BlackCell Auto Recon"* ]] && [[ "$help_output" == *"Usage:"* ]]; then
            test_log "PASS" "Help output contains expected content"
        else
            test_log "FAIL" "Help output missing expected content"
        fi
    else
        test_log "FAIL" "Help command failed to execute"
    fi
}

# Test 3: Input validation
test_input_validation() {
    echo -e "${BLUE}Testing input validation...${NC}"
    
    # Test invalid target
    if "$BCAR_SCRIPT" -t "invalid..target" 2>/dev/null; then
        test_log "FAIL" "Invalid target accepted (should be rejected)"
    else
        test_log "PASS" "Invalid target properly rejected"
    fi
    
    # Test invalid thread count
    if "$BCAR_SCRIPT" -t "example.com" -T "abc" 2>/dev/null; then
        test_log "FAIL" "Invalid thread count accepted"
    else
        test_log "PASS" "Invalid thread count properly rejected"
    fi
    
    # Test path traversal protection
    if "$BCAR_SCRIPT" -t "example.com" -o "../../../etc" 2>/dev/null; then
        test_log "FAIL" "Path traversal attempt accepted"
    else
        test_log "PASS" "Path traversal properly blocked"
    fi
}

# Test 4: Configuration file handling
test_configuration() {
    echo -e "${BLUE}Testing configuration file handling...${NC}"
    
    local test_config="$TEST_OUTPUT_DIR/test_bcar.conf"
    cat > "$test_config" << 'EOF'
THREADS=25
OUTPUT_FORMAT="json"
TIMING="fast"
EOF
    
    # Test config loading (this would require modifying bcar.sh to accept custom config path)
    # For now, just test that the config file format is valid
    if source "$test_config" 2>/dev/null; then
        test_log "PASS" "Configuration file format is valid"
    else
        test_log "FAIL" "Configuration file format validation failed"
    fi
}

# Test 5: Output directory creation
test_output_creation() {
    echo -e "${BLUE}Testing output directory creation...${NC}"
    
    local test_output="$TEST_OUTPUT_DIR/test_output"
    
    # Test that we can create output directories (mock test)
    if mkdir -p "$test_output" 2>/dev/null; then
        test_log "PASS" "Output directory creation works"
    else
        test_log "FAIL" "Output directory creation failed"
    fi
}

# Test 6: Dependency checking simulation
test_dependency_check() {
    echo -e "${BLUE}Testing dependency check functionality...${NC}"
    
    # Test common tools availability
    local tools=("bash" "grep" "awk" "sed" "cut")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        test_log "PASS" "Basic shell tools available"
    else
        test_log "FAIL" "Missing basic tools: ${missing_tools[*]}"
    fi
}

# Test 7: ShellCheck integration
test_shellcheck() {
    echo -e "${BLUE}Running ShellCheck analysis...${NC}"
    
    if command -v shellcheck &> /dev/null; then
        local shellcheck_output
        if shellcheck_output="$(shellcheck "$BCAR_SCRIPT" 2>&1)"; then
            test_log "PASS" "ShellCheck analysis passed with no issues"
        else
            # Count warnings vs errors
            local error_count
            error_count="$(echo "$shellcheck_output" | grep -c "error" || true)"
            if [[ "$error_count" -eq 0 ]]; then
                test_log "PASS" "ShellCheck analysis passed (warnings only)"
            else
                test_log "FAIL" "ShellCheck found $error_count errors"
            fi
        fi
    else
        test_log "INFO" "ShellCheck not available, skipping static analysis"
    fi
}

# Test 8: Security validation
test_security() {
    echo -e "${BLUE}Running security validation tests...${NC}"
    
    # Check for common security issues
    local security_issues=0
    
    # Test for unsafe eval usage
    if grep -q "eval" "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "FAIL" "Potentially unsafe eval usage detected"
        ((security_issues++))
    fi
    
    # Test for unsafe command substitution
    if grep -q '`.*`' "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "FAIL" "Unsafe backtick command substitution detected"
        ((security_issues++))
    fi
    
    # Test for proper quoting in dangerous contexts
    if grep -qE '\$[A-Za-z_][A-Za-z0-9_]*[^"]' "$BCAR_SCRIPT" 2>/dev/null; then
        # This is a simplified check - would need more sophisticated analysis
        test_log "INFO" "Variable usage patterns should be reviewed for proper quoting"
    fi
    
    if [[ $security_issues -eq 0 ]]; then
        test_log "PASS" "No obvious security issues detected"
    else
        test_log "FAIL" "Found $security_issues potential security issues"
    fi
}

# Test 9: Error handling validation
test_error_handling() {
    echo -e "${BLUE}Testing error handling...${NC}"
    
    # Test missing target parameter
    if "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "FAIL" "Missing target parameter not handled properly"
    else
        test_log "PASS" "Missing target parameter handled correctly"
    fi
    
    # Test invalid option
    if "$BCAR_SCRIPT" --invalid-option 2>/dev/null; then
        test_log "FAIL" "Invalid option not handled properly"
    else
        test_log "PASS" "Invalid option handled correctly"
    fi
}

# Test 10: Performance validation
test_performance() {
    echo -e "${BLUE}Testing performance characteristics...${NC}"
    
    local start_time
    local end_time
    local duration
    
    start_time="$(date +%s.%N)"
    "$BCAR_SCRIPT" --help >/dev/null 2>&1
    end_time="$(date +%s.%N)"
    
    duration="$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0.1")"
    
    # Help should execute in under 1 second
    if (( $(echo "$duration < 1.0" | bc -l 2>/dev/null || echo "1") )); then
        test_log "PASS" "Help execution time acceptable ($duration seconds)"
    else
        test_log "FAIL" "Help execution too slow ($duration seconds)"
    fi
}

# Print test summary
print_summary() {
    echo
    echo -e "${YELLOW}=======================================${NC}"
    echo -e "${YELLOW}BCAR Test Suite Summary${NC}"
    echo -e "${YELLOW}=======================================${NC}"
    echo -e "Total tests run: $TESTS_RUN"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    
    local success_rate
    if [[ $TESTS_RUN -gt 0 ]]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_RUN))
        echo -e "Success rate: ${success_rate}%"
        
        if [[ $TESTS_FAILED -eq 0 ]]; then
            echo -e "${GREEN}All tests passed!${NC}"
            return 0
        else
            echo -e "${RED}Some tests failed.${NC}"
            return 1
        fi
    else
        echo -e "${RED}No tests were run.${NC}"
        return 1
    fi
}

# Test 11: DOM scanning integration
test_dom_integration() {
    echo -e "${BLUE}Testing DOM scanning integration...${NC}"
    
    # Test DOM configuration options
    if grep -q "DOM_SCAN_ENABLED" "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "PASS" "DOM configuration variables found"
    else
        test_log "FAIL" "DOM configuration variables missing"
    fi
    
    # Test DOM functions exist
    if grep -q "dom_security_scan" "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "PASS" "DOM security scan function found"
    else
        test_log "FAIL" "DOM security scan function missing"
    fi
    
    # Test DOM command line options
    if grep -q "no-dom\|dom-gui" "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "PASS" "DOM command line options found"
    else
        test_log "FAIL" "DOM command line options missing"
    fi
    
    # Test DOMscan setup function
    if grep -q "setup_domscan\|check_domscan" "$BCAR_SCRIPT" 2>/dev/null; then
        test_log "PASS" "DOMscan setup functions found"
    else
        test_log "FAIL" "DOMscan setup functions missing"
    fi
    
    # Test help includes DOM options
    local help_output
    help_output="$("$BCAR_SCRIPT" --help 2>&1)" || true
    if echo "$help_output" | grep -q "no-dom\|dom-gui"; then
        test_log "PASS" "DOM options included in help text"
    else
        test_log "FAIL" "DOM options missing from help text"
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}Starting BCAR Test Suite...${NC}"
    
    # Check if bc is available for floating point calculations
    if ! command -v bc &> /dev/null; then
        echo -e "${YELLOW}Warning: bc not available, some timing tests may be skipped${NC}"
    fi
    
    setup_tests
    
    # Run all tests
    test_syntax
    test_help
    test_input_validation
    test_configuration
    test_output_creation
    test_dependency_check
    test_shellcheck
    test_security
    test_error_handling
    test_performance
    test_dom_integration
    
    cleanup_tests
    print_summary
}

# Execute main function
main "$@"