/*
Package profiling provides CPU/memory profiling for integration tests.

This file implements the Profiler for capturing runtime profiles and metrics.
*/
package profiling

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

// ProfilerConfig configures the Profiler
type ProfilerConfig struct {
	// OutputDir is the directory for profile files
	OutputDir string
	// EnableCPU enables CPU profiling
	EnableCPU bool
	// EnableMemory enables memory profiling
	EnableMemory bool
	// EnableGC enables GC stats collection
	EnableGC bool
	// SampleRate is the CPU profiling sample rate (Hz)
	SampleRate int
	// GenerateSVG generates SVG flamegraphs
	GenerateSVG bool
	// GenerateHTML generates HTML summary report
	GenerateHTML bool
}

// Profiler manages CPU and memory profiling for tests
type Profiler struct {
	config ProfilerConfig
	mu     sync.Mutex

	// Suite-level profiling
	suiteStartTime time.Time
	suiteCPUFile   *os.File
	suiteMetrics   *SuiteMetrics

	// Per-test profiling
	currentTest   string
	testStartTime time.Time
	testMemBefore MemoryStats
	testGCBefore  GCStats
	testCPUFile   *os.File

	// Collected metrics
	testMetrics []TestMetrics
}

// NewProfiler creates a new Profiler
func NewProfiler(config ProfilerConfig) *Profiler {
	if config.OutputDir == "" {
		config.OutputDir = "reports/profiling"
	}
	if config.SampleRate == 0 {
		config.SampleRate = 100
	}

	return &Profiler{
		config:      config,
		testMetrics: make([]TestMetrics, 0),
	}
}

// Start begins suite-level profiling
func (p *Profiler) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Create output directory
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	p.suiteStartTime = time.Now()
	p.suiteMetrics = &SuiteMetrics{
		SuiteName: "integration",
		StartTime: p.suiteStartTime,
	}

	// Start suite-level CPU profiling
	if p.config.EnableCPU {
		cpuFile, err := os.Create(filepath.Join(p.config.OutputDir, "suite_cpu.pprof"))
		if err != nil {
			return fmt.Errorf("failed to create CPU profile: %w", err)
		}
		p.suiteCPUFile = cpuFile

		runtime.SetCPUProfileRate(p.config.SampleRate)
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			cpuFile.Close()
			return fmt.Errorf("failed to start CPU profile: %w", err)
		}
	}

	return nil
}

// Stop ends suite-level profiling
func (p *Profiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop CPU profiling
	if p.suiteCPUFile != nil {
		pprof.StopCPUProfile()
		p.suiteCPUFile.Close()
		p.suiteMetrics.SuiteCPUProfile = filepath.Join(p.config.OutputDir, "suite_cpu.pprof")
	}

	// Capture final memory profile
	if p.config.EnableMemory {
		memFile, err := os.Create(filepath.Join(p.config.OutputDir, "suite_mem.pprof"))
		if err == nil {
			runtime.GC() // Get accurate memory stats
			if writeErr := pprof.WriteHeapProfile(memFile); writeErr != nil {
				// Log but don't fail - profiling is non-critical
				fmt.Fprintf(os.Stderr, "warning: failed to write heap profile: %v\n", writeErr)
			}
			memFile.Close()
			p.suiteMetrics.SuiteMemProfile = filepath.Join(p.config.OutputDir, "suite_mem.pprof")
		}
	}

	// Finalize suite metrics
	p.suiteMetrics.EndTime = time.Now()
	p.suiteMetrics.Duration = p.suiteMetrics.EndTime.Sub(p.suiteStartTime)
	p.suiteMetrics.Tests = p.testMetrics
	p.suiteMetrics.TotalTests = len(p.testMetrics)

	// Calculate aggregates
	var peakMem uint64
	var totalAlloc uint64
	var totalGCPause time.Duration

	for _, tm := range p.testMetrics {
		if tm.MemoryAfter.Alloc > peakMem {
			peakMem = tm.MemoryAfter.Alloc
		}
		totalAlloc += uint64(tm.MemoryDelta.TotalAllocDelta)
		totalGCPause += time.Duration(tm.GCDelta.PauseTotalDelta)
	}

	p.suiteMetrics.PeakMemory = peakMem
	p.suiteMetrics.TotalAllocated = totalAlloc
	p.suiteMetrics.TotalGCPauses = totalGCPause

	return nil
}

// BeginTest starts profiling for a specific test
func (p *Profiler) BeginTest(testName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Sanitize test name for filesystem
	safeName := sanitizeTestName(testName)

	p.currentTest = testName
	p.testStartTime = time.Now()

	// Create test-specific directory
	testDir := filepath.Join(p.config.OutputDir, safeName)
	os.MkdirAll(testDir, 0755) //nolint:errcheck

	// Capture before stats
	if p.config.EnableMemory {
		runtime.GC() // Clean slate for memory comparison
		p.testMemBefore = CaptureMemoryStats()
	}
	if p.config.EnableGC {
		p.testGCBefore = CaptureGCStats()
	}

	// Start per-test CPU profiling
	if p.config.EnableCPU {
		cpuFile, err := os.Create(filepath.Join(testDir, "cpu.pprof"))
		if err == nil {
			p.testCPUFile = cpuFile
			// Note: We can't have multiple CPU profiles running simultaneously
			// The suite-level profile captures all, test-level profiles are for flamegraphs
		}
	}
}

// EndTest completes profiling for the current test
func (p *Profiler) EndTest(testName string, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentTest != testName {
		return // Not the expected test
	}

	safeName := sanitizeTestName(testName)
	testDir := filepath.Join(p.config.OutputDir, safeName)

	metrics := TestMetrics{
		TestName:  testName,
		StartTime: p.testStartTime,
		EndTime:   time.Now(),
		Duration:  duration,
	}

	// Capture after stats and calculate delta
	if p.config.EnableMemory {
		metrics.MemoryBefore = p.testMemBefore
		metrics.MemoryAfter = CaptureMemoryStats()
		metrics.MemoryDelta = CalculateMemoryDelta(p.testMemBefore, metrics.MemoryAfter)

		// Write memory profile
		memFile, err := os.Create(filepath.Join(testDir, "mem.pprof"))
		if err == nil {
			if writeErr := pprof.WriteHeapProfile(memFile); writeErr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write heap profile: %v\n", writeErr)
			}
			memFile.Close()
			metrics.MemProfilePath = filepath.Join(testDir, "mem.pprof")
		}
	}

	if p.config.EnableGC {
		metrics.GCBefore = p.testGCBefore
		metrics.GCAfter = CaptureGCStats()
		metrics.GCDelta = CalculateGCDelta(p.testGCBefore, metrics.GCAfter)
	}

	// Close CPU profile
	if p.testCPUFile != nil {
		p.testCPUFile.Close()
		metrics.CPUProfilePath = filepath.Join(testDir, "cpu.pprof")
		p.testCPUFile = nil
	}

	p.testMetrics = append(p.testMetrics, metrics)
	p.currentTest = ""
}

// GenerateReport generates the profiling report
func (p *Profiler) GenerateReport() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.suiteMetrics == nil {
		return fmt.Errorf("no metrics collected")
	}

	reporter := NewReporter(p.config.OutputDir, p.suiteMetrics)

	// Generate flamegraphs if enabled
	if p.config.GenerateSVG {
		if err := reporter.GenerateFlamegraphs(); err != nil {
			// Don't fail on flamegraph errors - pprof might not be available
			fmt.Printf("Warning: failed to generate flamegraphs: %v\n", err)
		}
	}

	// Generate HTML report if enabled
	if p.config.GenerateHTML {
		if err := reporter.GenerateHTMLReport(); err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
	}

	// Export JSON metrics
	if err := reporter.ExportJSON(); err != nil {
		return fmt.Errorf("failed to export JSON metrics: %w", err)
	}

	return nil
}

// GetMetrics returns the collected suite metrics
func (p *Profiler) GetMetrics() *SuiteMetrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.suiteMetrics
}

// sanitizeTestName converts a test name to a safe filesystem path
func sanitizeTestName(name string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
		"[", "",
		"]", "",
	)
	safe := replacer.Replace(name)

	// Truncate if too long
	if len(safe) > 100 {
		safe = safe[:100]
	}

	return safe
}
