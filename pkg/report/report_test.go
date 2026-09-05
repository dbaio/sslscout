package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dbaio/sslscout/pkg/checker"
)

func res(domain string, status checker.Status, days int) checker.Result {
	return checker.Result{
		Domain:        domain,
		Host:          strings.Split(domain, ":")[0],
		Port:          443,
		Status:        status,
		Valid:         status.Valid(),
		DaysRemaining: days,
	}
}

func TestBuildOrdering(t *testing.T) {
	input := []checker.Result{
		res("ok-b.example.com:443", checker.StatusOK, 200),
		res("warning.example.com:443", checker.StatusWarning, 12),
		res("error.example.com:443", checker.StatusError, 0),
		res("ok-a.example.com:443", checker.StatusOK, 200),
		res("expired.example.com:443", checker.StatusExpired, -30),
		res("critical.example.com:443", checker.StatusCritical, 3),
		res("invalid.example.com:443", checker.StatusInvalid, 40),
	}

	rep := Build(input, time.Now(), 1500*time.Millisecond, 15, 7)

	want := []string{
		"error.example.com:443",   // worst status first
		"expired.example.com:443", //
		"invalid.example.com:443", //
		"critical.example.com:443",
		"warning.example.com:443",
		"ok-a.example.com:443", // same status and deadline: alphabetical
		"ok-b.example.com:443",
	}
	for i, w := range want {
		if rep.Results[i].Domain != w {
			t.Errorf("results[%d] = %q, want %q", i, rep.Results[i].Domain, w)
		}
	}

	if rep.SchemaVersion != 2 {
		t.Errorf("schema_version = %d, want 2", rep.SchemaVersion)
	}
	if rep.DurationMS != 1500 {
		t.Errorf("duration_ms = %d, want 1500", rep.DurationMS)
	}
	if rep.AlertThresholdDays != 15 || rep.CriticalThresholdDays != 7 {
		t.Errorf("thresholds = %d/%d", rep.AlertThresholdDays, rep.CriticalThresholdDays)
	}
	if rep.GeneratedAt.Location() != time.UTC {
		t.Errorf("generated_at should be in UTC, got %v", rep.GeneratedAt.Location())
	}
}

func TestBuildTieBreakByDeadline(t *testing.T) {
	input := []checker.Result{
		res("z.example.com:443", checker.StatusWarning, 3),
		res("a.example.com:443", checker.StatusWarning, 14),
		res("m.example.com:443", checker.StatusWarning, 3),
	}
	rep := Build(input, time.Now(), 0, 15, 7)

	want := []string{"m.example.com:443", "z.example.com:443", "a.example.com:443"}
	for i, w := range want {
		if rep.Results[i].Domain != w {
			t.Errorf("results[%d] = %q, want %q", i, rep.Results[i].Domain, w)
		}
	}
}

func TestBuildDoesNotMutateInput(t *testing.T) {
	input := []checker.Result{
		res("b.example.com:443", checker.StatusOK, 10),
		res("a.example.com:443", checker.StatusError, 0),
	}
	Build(input, time.Now(), 0, 15, 7)
	if input[0].Domain != "b.example.com:443" {
		t.Error("Build should not reorder the original slice")
	}
}

func TestSummarize(t *testing.T) {
	input := []checker.Result{
		res("a:443", checker.StatusOK, 100),
		res("b:443", checker.StatusOK, 90),
		res("c:443", checker.StatusWarning, 10),
		res("d:443", checker.StatusCritical, 2),
		res("e:443", checker.StatusExpired, -5),
		res("f:443", checker.StatusInvalid, 30),
		res("g:443", checker.StatusError, 0),
	}
	s := Summarize(input)
	want := Summary{Total: 7, OK: 2, Warning: 1, Critical: 1, Expired: 1, Invalid: 1, Error: 1}
	if s != want {
		t.Errorf("summary = %+v, want %+v", s, want)
	}
}

func TestWorstSeverity(t *testing.T) {
	empty := Build(nil, time.Now(), 0, 15, 7)
	if empty.WorstSeverity() != -1 {
		t.Errorf("an empty report should have severity -1, got %d", empty.WorstSeverity())
	}
	rep := Build([]checker.Result{
		res("a:443", checker.StatusOK, 100),
		res("b:443", checker.StatusCritical, 2),
	}, time.Now(), 0, 15, 7)
	if rep.WorstSeverity() != checker.StatusCritical.Severity() {
		t.Errorf("worst severity = %d, want %d", rep.WorstSeverity(), checker.StatusCritical.Severity())
	}
}

func TestBuildResultsIsNeverNull(t *testing.T) {
	data, err := json.Marshal(Build(nil, time.Now(), 0, 15, 7))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"results":[]`) {
		t.Errorf("results should come out as [], not null: %s", data)
	}
}

func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "report.json")

	rep := Build([]checker.Result{res("a.example.com:443", checker.StatusOK, 100)},
		time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC), 42*time.Millisecond, 15, 7)

	if err := Write(path, rep); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the report was not created: %v", err)
	}
	var read Report
	if err := json.Unmarshal(data, &read); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if read.Summary.Total != 1 || read.SchemaVersion != 2 {
		t.Errorf("unexpected content: %+v", read.Summary)
	}

	// Rewriting the same path replaces it and leaves no temporary litter.
	rep.Results[0].Domain = "b.example.com:443"
	if err := Write(path, rep); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "report.json" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory should hold report.json only, got %v", names)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("permissions = %v, want 0644", info.Mode().Perm())
	}
}

func TestWriteDirectoryError(t *testing.T) {
	// A regular file where the directory should be makes MkdirAll fail.
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Write(filepath.Join(file, "report.json"), Build(nil, time.Now(), 0, 15, 7))
	if err == nil {
		t.Fatal("Write should fail when the directory cannot be created")
	}
}
