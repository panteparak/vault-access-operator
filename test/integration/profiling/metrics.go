/*
Package profiling provides CPU/memory profiling and report generation for integration tests.

This file defines metrics collection types for tracking test performance.
*/
package profiling

import (
	"runtime"
	"time"
)

// TestMetrics holds performance metrics for a single test
type TestMetrics struct {
	// Test identification
	TestName  string        `json:"test_name"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Memory metrics
	MemoryBefore MemoryStats `json:"memory_before"`
	MemoryAfter  MemoryStats `json:"memory_after"`
	MemoryDelta  MemoryDelta `json:"memory_delta"`

	// GC metrics
	GCBefore GCStats `json:"gc_before"`
	GCAfter  GCStats `json:"gc_after"`
	GCDelta  GCDelta `json:"gc_delta"`

	// Profile file paths
	CPUProfilePath    string `json:"cpu_profile_path,omitempty"`
	MemProfilePath    string `json:"mem_profile_path,omitempty"`
	CPUFlamegraphPath string `json:"cpu_flamegraph_path,omitempty"`
	MemFlamegraphPath string `json:"mem_flamegraph_path,omitempty"`
}

// MemoryStats captures heap memory statistics
type MemoryStats struct {
	// Bytes allocated and in use
	Alloc uint64 `json:"alloc"`
	// Total bytes allocated (cumulative)
	TotalAlloc uint64 `json:"total_alloc"`
	// Bytes obtained from system
	Sys uint64 `json:"sys"`
	// Number of heap objects
	HeapObjects uint64 `json:"heap_objects"`
	// Heap size in use
	HeapInuse uint64 `json:"heap_inuse"`
	// Number of allocations
	Mallocs uint64 `json:"mallocs"`
	// Number of frees
	Frees uint64 `json:"frees"`
}

// MemoryDelta represents the change in memory stats
type MemoryDelta struct {
	AllocDelta       int64 `json:"alloc_delta"`
	TotalAllocDelta  int64 `json:"total_alloc_delta"`
	HeapObjectsDelta int64 `json:"heap_objects_delta"`
	MallocsDelta     int64 `json:"mallocs_delta"`
}

// GCStats captures garbage collection statistics
type GCStats struct {
	// Number of completed GC cycles
	NumGC uint32 `json:"num_gc"`
	// Total pause time in all GC cycles
	PauseTotalNs uint64 `json:"pause_total_ns"`
	// Last GC pause time
	LastPauseNs uint64 `json:"last_pause_ns"`
}

// GCDelta represents the change in GC stats
type GCDelta struct {
	NumGCDelta       int32         `json:"num_gc_delta"`
	PauseTotalDelta  int64         `json:"pause_total_delta_ns"`
	AvgPausePerCycle time.Duration `json:"avg_pause_per_cycle"`
}

// SuiteMetrics aggregates metrics for the entire test suite
type SuiteMetrics struct {
	// Suite identification
	SuiteName string        `json:"suite_name"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Test results
	TotalTests  int `json:"total_tests"`
	PassedTests int `json:"passed_tests"`
	FailedTests int `json:"failed_tests"`

	// Individual test metrics
	Tests []TestMetrics `json:"tests"`

	// Aggregate memory stats
	PeakMemory     uint64        `json:"peak_memory"`
	TotalAllocated uint64        `json:"total_allocated"`
	TotalGCPauses  time.Duration `json:"total_gc_pauses"`

	// Profile paths
	SuiteCPUProfile string `json:"suite_cpu_profile,omitempty"`
	SuiteMemProfile string `json:"suite_mem_profile,omitempty"`
}

// CaptureMemoryStats captures current memory statistics
func CaptureMemoryStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemoryStats{
		Alloc:       m.Alloc,
		TotalAlloc:  m.TotalAlloc,
		Sys:         m.Sys,
		HeapObjects: m.HeapObjects,
		HeapInuse:   m.HeapInuse,
		Mallocs:     m.Mallocs,
		Frees:       m.Frees,
	}
}

// CaptureGCStats captures current GC statistics
func CaptureGCStats() GCStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	lastPause := uint64(0)
	if m.NumGC > 0 {
		lastPause = m.PauseNs[(m.NumGC+255)%256]
	}

	return GCStats{
		NumGC:        m.NumGC,
		PauseTotalNs: m.PauseTotalNs,
		LastPauseNs:  lastPause,
	}
}

// CalculateMemoryDelta calculates the difference between two memory snapshots
func CalculateMemoryDelta(before, after MemoryStats) MemoryDelta {
	return MemoryDelta{
		AllocDelta:       int64(after.Alloc) - int64(before.Alloc),
		TotalAllocDelta:  int64(after.TotalAlloc) - int64(before.TotalAlloc),
		HeapObjectsDelta: int64(after.HeapObjects) - int64(before.HeapObjects),
		MallocsDelta:     int64(after.Mallocs) - int64(before.Mallocs),
	}
}

// CalculateGCDelta calculates the difference between two GC snapshots
func CalculateGCDelta(before, after GCStats) GCDelta {
	gcCycles := int32(after.NumGC) - int32(before.NumGC)
	pauseDelta := int64(after.PauseTotalNs) - int64(before.PauseTotalNs)

	avgPause := time.Duration(0)
	if gcCycles > 0 {
		avgPause = time.Duration(pauseDelta / int64(gcCycles))
	}

	return GCDelta{
		NumGCDelta:       gcCycles,
		PauseTotalDelta:  pauseDelta,
		AvgPausePerCycle: avgPause,
	}
}

// FormatBytes formats bytes into a human-readable string
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return formatWithCommas(bytes) + " B"
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return formatFloat(float64(bytes)/float64(div)) + " " + string("KMGTPE"[exp]) + "iB"
}

func formatWithCommas(n uint64) string {
	s := ""
	for n >= 1000 {
		s = "," + padLeft(n%1000, 3) + s
		n /= 1000
	}
	return padLeft(n, 0) + s
}

func padLeft(n uint64, width int) string {
	s := ""
	for n > 0 || len(s) < width {
		s = string('0'+byte(n%10)) + s
		n /= 10
	}
	if s == "" {
		s = "0"
	}
	return s
}

func formatFloat(f float64) string {
	if f < 10 {
		return formatFloatPrec(f, 2)
	} else if f < 100 {
		return formatFloatPrec(f, 1)
	}
	return formatFloatPrec(f, 0)
}

func formatFloatPrec(f float64, prec int) string {
	if prec == 0 {
		return padLeft(uint64(f+0.5), 0)
	}
	whole := uint64(f)
	frac := f - float64(whole)
	for i := 0; i < prec; i++ {
		frac *= 10
	}
	return padLeft(whole, 0) + "." + padLeft(uint64(frac+0.5), prec)
}
