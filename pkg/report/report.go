// Package report builds, sorts and atomically writes the report.json v2.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dbaio/sslscout/pkg/checker"
)

// SchemaVersion of the format emitted by this package.
const SchemaVersion = 2

// Summary is the per-status count.
type Summary struct {
	Total    int `json:"total"`
	OK       int `json:"ok"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
	Expired  int `json:"expired"`
	Invalid  int `json:"invalid"`
	Error    int `json:"error"`
}

// Report is the whole document consumed by the dashboard.
type Report struct {
	SchemaVersion         int              `json:"schema_version"`
	GeneratedAt           time.Time        `json:"generated_at"`
	DurationMS            int64            `json:"duration_ms"`
	AlertThresholdDays    int              `json:"alert_threshold_days"`
	CriticalThresholdDays int              `json:"critical_threshold_days"`
	Summary               Summary          `json:"summary"`
	Results               []checker.Result `json:"results"`
}

// Build assembles the report: it sorts the results and computes the summary.
//
// Ordering (deterministic and stable): worst status first (by
// checker.Status severity), then the smallest days_remaining, then the domain
// alphabetically. The idea is that whoever opens the dashboard sees what needs
// action at the top, and that two reports over the same data are byte for byte
// identical.
func Build(results []checker.Result, generatedAt time.Time, duration time.Duration, alert, critical int) *Report {
	// make() guarantees a non-nil slice: "results" comes out as [], never null.
	sorted := make([]checker.Result, len(results))
	copy(sorted, results)

	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if sa, sb := a.Status.Severity(), b.Status.Severity(); sa != sb {
			return sa > sb
		}
		// The effective deadline, not the leaf's: a host whose chain dies in
		// two days belongs above one whose own certificate dies in ten.
		if da, db := a.EffectiveDaysRemaining(), b.EffectiveDaysRemaining(); da != db {
			return da < db
		}
		return a.Domain < b.Domain
	})

	return &Report{
		SchemaVersion:         SchemaVersion,
		GeneratedAt:           generatedAt.UTC(),
		DurationMS:            duration.Milliseconds(),
		AlertThresholdDays:    alert,
		CriticalThresholdDays: critical,
		Summary:               Summarize(sorted),
		Results:               sorted,
	}
}

// Summarize counts the results per status.
func Summarize(results []checker.Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case checker.StatusOK:
			s.OK++
		case checker.StatusWarning:
			s.Warning++
		case checker.StatusCritical:
			s.Critical++
		case checker.StatusExpired:
			s.Expired++
		case checker.StatusInvalid:
			s.Invalid++
		case checker.StatusError:
			s.Error++
		}
	}
	return s
}

// WorstSeverity returns the severity of the worst result (-1 when empty).
func (r *Report) WorstSeverity() int {
	worst := -1
	for _, res := range r.Results {
		if s := res.Status.Severity(); s > worst {
			worst = s
		}
	}
	return worst
}

// Write stores the report atomically: it writes to a temporary file in the same
// directory, syncs it and renames. That way the dashboard never reads a
// truncated JSON, even if the process dies mid-write.
func Write(path string, r *Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("could not serialize the report: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("could not create the directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("could not create the temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("could not write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("could not sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("could not set the permissions of %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("could not publish the report to %s: %w", path, err)
	}
	return nil
}
