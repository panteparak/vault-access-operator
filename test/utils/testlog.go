/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
)

// stepTimer tracks timing between steps for TimedBy
var (
	stepStartTime time.Time
	stepMu        sync.Mutex
)

// TimedBy wraps Ginkgo's By() with elapsed time since last step.
// Output format: "step description [+123ms]"
// This helps identify slow test steps during debugging.
func TimedBy(description string) {
	stepMu.Lock()
	elapsed := ""
	if !stepStartTime.IsZero() {
		elapsed = fmt.Sprintf(" [+%v]", time.Since(stepStartTime).Round(time.Millisecond))
	}
	stepStartTime = time.Now()
	stepMu.Unlock()

	By(description + elapsed)
}

// ResetStepTimer resets the step timer (call at start of each test if needed)
func ResetStepTimer() {
	stepMu.Lock()
	stepStartTime = time.Time{}
	stepMu.Unlock()
}

// TestContext provides structured logging for a test with timing information.
// Use NewTestContext() at the start of a test and call Summary() at the end.
type TestContext struct {
	TestName  string
	StartTime time.Time
}

// NewTestContext creates a new test context for structured logging.
// It logs a test start banner with the test name.
func NewTestContext(name string) *TestContext {
	tc := &TestContext{
		TestName:  name,
		StartTime: time.Now(),
	}
	fmt.Fprintf(GinkgoWriter, "\n=== TEST: %s ===\n", name)
	return tc
}

// Log writes a structured log entry with elapsed time from test start.
// Format: "[123ms] message"
func (tc *TestContext) Log(format string, args ...interface{}) {
	elapsed := time.Since(tc.StartTime).Round(time.Millisecond)
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(GinkgoWriter, "[%v] %s\n", elapsed, msg)
}

// LogError writes an error with context information.
// The context map allows adding key-value pairs for debugging.
func (tc *TestContext) LogError(operation string, err error, context map[string]string) {
	elapsed := time.Since(tc.StartTime).Round(time.Millisecond)
	fmt.Fprintf(GinkgoWriter, "[%v] ERROR in %s: %v\n", elapsed, operation, err)
	for k, v := range context {
		fmt.Fprintf(GinkgoWriter, "  %s: %s\n", k, v)
	}
}

// Summary logs test completion with total duration.
// Call this at the end of a test (e.g., in a deferred function or AfterEach).
func (tc *TestContext) Summary() {
	duration := time.Since(tc.StartTime)
	fmt.Fprintf(GinkgoWriter, "=== END %s (took %v) ===\n\n", tc.TestName, duration.Round(time.Millisecond))
}

// LogSection writes a section header to GinkgoWriter for visual separation.
// Useful for grouping related log output.
func LogSection(name string) {
	fmt.Fprintf(GinkgoWriter, "\n--- %s ---\n", name)
}

// LogKeyValue writes a key-value pair to GinkgoWriter.
// Useful for logging state information.
func LogKeyValue(key, value string) {
	fmt.Fprintf(GinkgoWriter, "  %s: %s\n", key, value)
}
