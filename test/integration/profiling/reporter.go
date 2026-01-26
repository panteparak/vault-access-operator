/*
Package profiling provides report generation for integration test profiling.

This file implements HTML/SVG report generation from collected metrics.
*/
package profiling

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Reporter generates profiling reports
type Reporter struct {
	outputDir string
	metrics   *SuiteMetrics
}

// NewReporter creates a new Reporter
func NewReporter(outputDir string, metrics *SuiteMetrics) *Reporter {
	return &Reporter{
		outputDir: outputDir,
		metrics:   metrics,
	}
}

// GenerateFlamegraphs generates SVG flamegraphs from pprof files
func (r *Reporter) GenerateFlamegraphs() error {
	// Check if go tool pprof is available
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go command not found: %w", err)
	}

	// Generate suite-level flamegraphs
	if r.metrics.SuiteCPUProfile != "" {
		svgPath := strings.TrimSuffix(r.metrics.SuiteCPUProfile, ".pprof") + "_flamegraph.svg"
		if err := r.generateSVG(r.metrics.SuiteCPUProfile, svgPath); err != nil {
			return fmt.Errorf("failed to generate suite CPU flamegraph: %w", err)
		}
	}

	if r.metrics.SuiteMemProfile != "" {
		svgPath := strings.TrimSuffix(r.metrics.SuiteMemProfile, ".pprof") + "_flamegraph.svg"
		if err := r.generateSVG(r.metrics.SuiteMemProfile, svgPath); err != nil {
			return fmt.Errorf("failed to generate suite memory flamegraph: %w", err)
		}
	}

	// Generate per-test flamegraphs
	for i := range r.metrics.Tests {
		test := &r.metrics.Tests[i]

		if test.CPUProfilePath != "" {
			svgPath := strings.TrimSuffix(test.CPUProfilePath, ".pprof") + "_flamegraph.svg"
			if err := r.generateSVG(test.CPUProfilePath, svgPath); err == nil {
				test.CPUFlamegraphPath = svgPath
			}
		}

		if test.MemProfilePath != "" {
			svgPath := strings.TrimSuffix(test.MemProfilePath, ".pprof") + "_flamegraph.svg"
			if err := r.generateSVG(test.MemProfilePath, svgPath); err == nil {
				test.MemFlamegraphPath = svgPath
			}
		}
	}

	return nil
}

// generateSVG runs go tool pprof to generate an SVG flamegraph
func (r *Reporter) generateSVG(pprofPath, svgPath string) error {
	cmd := exec.Command("go", "tool", "pprof", "-svg", "-output="+svgPath, pprofPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pprof failed: %s: %w", output, err)
	}
	return nil
}

// GenerateHTMLReport generates an HTML summary report
func (r *Reporter) GenerateHTMLReport() error {
	reportPath := filepath.Join(r.outputDir, "summary.html")
	f, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatBytes":    FormatBytes,
		"formatDuration": formatDuration,
		"formatTime":     formatTime,
		"relPath":        r.relativePath,
		"abs":            abs,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(f, r.metrics); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// ExportJSON exports metrics as JSON
func (r *Reporter) ExportJSON() error {
	jsonPath := filepath.Join(r.outputDir, "metrics.json")
	f, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r.metrics); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

func (r *Reporter) relativePath(path string) string {
	rel, err := filepath.Rel(r.outputDir, path)
	if err != nil {
		return path
	}
	return rel
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fμs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Integration Test Profiling Report</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --text-primary: #e4e4e4;
            --text-secondary: #a4a4a4;
            --accent: #e94560;
            --success: #00d09c;
            --warning: #ffc107;
            --border: #2a2a4a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--accent), #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle { color: var(--text-secondary); margin-bottom: 2rem; }
        .card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }
        .card-title {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .stat-item {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        .stat-label { font-size: 0.875rem; color: var(--text-secondary); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: var(--bg-tertiary);
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        tr:hover { background: rgba(233, 69, 96, 0.1); }
        .positive { color: var(--success); }
        .negative { color: var(--accent); }
        .flamegraph-link {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: var(--bg-tertiary);
            border-radius: 4px;
            color: var(--accent);
            text-decoration: none;
            font-size: 0.875rem;
            margin-right: 0.5rem;
        }
        .flamegraph-link:hover { background: var(--accent); color: white; }
        .flamegraph-container {
            margin-top: 1rem;
            background: white;
            border-radius: 8px;
            padding: 1rem;
        }
        .flamegraph-container object {
            width: 100%;
            height: 400px;
        }
        .timestamp { font-size: 0.875rem; color: var(--text-secondary); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Integration Test Profiling Report</h1>
        <p class="subtitle">Generated: {{formatTime .EndTime}}</p>

        <div class="card">
            <h2 class="card-title">Suite Summary</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">{{.TotalTests}}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatDuration .Duration}}</div>
                    <div class="stat-label">Total Duration</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatBytes .PeakMemory}}</div>
                    <div class="stat-label">Peak Memory</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatBytes .TotalAllocated}}</div>
                    <div class="stat-label">Total Allocated</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatDuration .TotalGCPauses}}</div>
                    <div class="stat-label">Total GC Pauses</div>
                </div>
            </div>
        </div>

        {{if .SuiteCPUProfile}}
        <div class="card">
            <h2 class="card-title">Suite CPU Profile</h2>
            <a class="flamegraph-link" href="{{relPath .SuiteCPUProfile}}" download>Download .pprof</a>
            {{if .SuiteCPUProfile}}
            <div class="flamegraph-container">
                <object data="suite_cpu_flamegraph.svg" type="image/svg+xml">
                    CPU flamegraph not available
                </object>
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="card">
            <h2 class="card-title">Test Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Test Name</th>
                        <th>Duration</th>
                        <th>Memory Δ</th>
                        <th>Allocs Δ</th>
                        <th>GC Cycles</th>
                        <th>GC Pause</th>
                        <th>Profiles</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Tests}}
                    <tr>
                        <td>{{.TestName}}</td>
                        <td>{{formatDuration .Duration}}</td>
                        <td class="{{if gt .MemoryDelta.AllocDelta 0}}negative{{else}}positive{{end}}">
                            {{formatBytes (abs .MemoryDelta.AllocDelta)}}
                        </td>
                        <td>{{.MemoryDelta.MallocsDelta}}</td>
                        <td>{{.GCDelta.NumGCDelta}}</td>
                        <td>{{formatDuration .GCDelta.AvgPausePerCycle}}</td>
                        <td>
                            {{if .CPUProfilePath}}
                            <a class="flamegraph-link" href="{{relPath .CPUProfilePath}}" download>CPU</a>
                            {{end}}
                            {{if .MemProfilePath}}
                            <a class="flamegraph-link" href="{{relPath .MemProfilePath}}" download>Mem</a>
                            {{end}}
                            {{if .CPUFlamegraphPath}}
                            <a class="flamegraph-link" href="{{relPath .CPUFlamegraphPath}}">CPU SVG</a>
                            {{end}}
                            {{if .MemFlamegraphPath}}
                            <a class="flamegraph-link" href="{{relPath .MemFlamegraphPath}}">Mem SVG</a>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <p class="timestamp">Report generated by vault-access-operator integration test profiler</p>
    </div>

    <script>
        // Add simple sorting to tables
        document.querySelectorAll('th').forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => {
                const table = header.closest('table');
                const idx = Array.from(header.parentNode.children).indexOf(header);
                const rows = Array.from(table.querySelectorAll('tbody tr'));
                const asc = header.dataset.sort !== 'asc';
                header.dataset.sort = asc ? 'asc' : 'desc';
                rows.sort((a, b) => {
                    const aVal = a.children[idx].textContent;
                    const bVal = b.children[idx].textContent;
                    return asc ? aVal.localeCompare(bVal, undefined, {numeric: true})
                               : bVal.localeCompare(aVal, undefined, {numeric: true});
                });
                rows.forEach(row => table.querySelector('tbody').appendChild(row));
            });
        });
    </script>
</body>
</html>`

// abs returns the absolute value of an int64
func abs(n int64) uint64 {
	if n < 0 {
		return uint64(-n)
	}
	return uint64(n)
}
