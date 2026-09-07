package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dbaio/sslscout/pkg/checker"
)

func result(domain string, status checker.Status, days int, expires time.Time) checker.Result {
	r := checker.Result{Domain: domain, Status: status, DaysRemaining: days}
	if !expires.IsZero() {
		r.ExpiresAt = &expires
	}
	return r
}

// TestPendingPolicy is the whole point of the package: what gets through and
// what stays quiet on the second run.
func TestPendingPolicy(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expires := now.Add(12 * 24 * time.Hour)

	cases := []struct {
		name    string
		first   checker.Result // announced at "now"
		second  checker.Result // evaluated at "now + later"
		later   time.Duration
		wantOut bool
	}{
		{
			name:    "same problem an hour later stays quiet",
			first:   result("a.test:443", checker.StatusWarning, 12, expires),
			second:  result("a.test:443", checker.StatusWarning, 12, expires),
			later:   time.Hour,
			wantOut: false,
		},
		{
			name:    "the same problem is repeated after a day",
			first:   result("a.test:443", checker.StatusWarning, 12, expires),
			second:  result("a.test:443", checker.StatusWarning, 11, expires),
			later:   25 * time.Hour,
			wantOut: true,
		},
		{
			name:    "a change of status always gets through",
			first:   result("a.test:443", checker.StatusWarning, 12, expires),
			second:  result("a.test:443", checker.StatusCritical, 6, expires),
			later:   time.Hour,
			wantOut: true,
		},
		{
			// 20 days sits on the 30 rung, 12 on the 14 one. The status has not
			// moved, and it is still news: "two weeks" is a different
			// conversation with whoever owns the certificate.
			name:    "crossing a rung of the ladder gets through",
			first:   result("a.test:443", checker.StatusWarning, 20, expires),
			second:  result("a.test:443", checker.StatusWarning, 12, expires),
			later:   time.Hour,
			wantOut: true,
		},
		{
			name:    "moving inside the same rung stays quiet",
			first:   result("a.test:443", checker.StatusWarning, 13, expires),
			second:  result("a.test:443", checker.StatusWarning, 12, expires),
			later:   time.Hour,
			wantOut: false,
		},
		{
			name:    "a replaced certificate that is still a problem gets through",
			first:   result("a.test:443", checker.StatusWarning, 12, expires),
			second:  result("a.test:443", checker.StatusWarning, 12, expires.Add(48*time.Hour)),
			later:   time.Hour,
			wantOut: true,
		},
		{
			name:    "a connection failure is not repeated every run",
			first:   result("a.test:443", checker.StatusError, 0, time.Time{}),
			second:  result("a.test:443", checker.StatusError, 0, time.Time{}),
			later:   time.Hour,
			wantOut: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New()

			first := s.Pending([]checker.Result{c.first}, now, DefaultRepeatAfter)
			if len(first) != 1 {
				t.Fatalf("the first run should always announce, got %d", len(first))
			}
			s.Record(first, now)

			later := now.Add(c.later)
			got := s.Pending([]checker.Result{c.second}, later, DefaultRepeatAfter)
			if (len(got) > 0) != c.wantOut {
				t.Fatalf("second run announced %d result(s), want announced=%v", len(got), c.wantOut)
			}
		})
	}
}

func TestPendingIgnoresHealthyResults(t *testing.T) {
	now := time.Now()
	s := New()
	if got := s.Pending([]checker.Result{result("a.test:443", checker.StatusOK, 90, now.Add(90*24*time.Hour))}, now, DefaultRepeatAfter); len(got) != 0 {
		t.Fatalf("an ok result should never be announced, got %d", len(got))
	}
}

// TestRecoveryClearsTheHistory: after a certificate is renewed, the next
// problem has to alert immediately rather than fall inside the quiet window of
// the previous one.
func TestRecoveryClearsTheHistory(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expires := now.Add(3 * 24 * time.Hour)
	s := New()

	problem := []checker.Result{result("a.test:443", checker.StatusCritical, 3, expires)}
	s.Record(s.Pending(problem, now, DefaultRepeatAfter), now)

	healthy := []checker.Result{result("a.test:443", checker.StatusOK, 90, now.Add(90*24*time.Hour))}
	s.Sync(healthy, now.Add(time.Hour))
	if len(s.Domains) != 0 {
		t.Fatalf("the entry should have been forgotten, state = %+v", s.Domains)
	}

	again := []checker.Result{result("a.test:443", checker.StatusCritical, 3, expires)}
	if got := s.Pending(again, now.Add(2*time.Hour), DefaultRepeatAfter); len(got) != 1 {
		t.Fatal("a problem coming back should be announced right away")
	}
}

func TestSyncForgetsDomainsThatLeftTheList(t *testing.T) {
	now := time.Now()
	s := New()
	s.Record([]checker.Result{
		result("a.test:443", checker.StatusWarning, 10, now.Add(10*24*time.Hour)),
		result("b.test:443", checker.StatusWarning, 10, now.Add(10*24*time.Hour)),
	}, now)

	s.Sync([]checker.Result{result("a.test:443", checker.StatusWarning, 10, now.Add(10*24*time.Hour))}, now)

	if _, still := s.Domains["b.test:443"]; still {
		t.Error("a domain that left domains.txt should not stay in the state forever")
	}
	if _, still := s.Domains["a.test:443"]; !still {
		t.Error("a domain that still has a problem must be kept")
	}
}

// TestRepeatDisabled: repeat_hours = 0 means only a real change gets through.
func TestRepeatDisabled(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expires := now.Add(12 * 24 * time.Hour)
	s := New()

	first := []checker.Result{result("a.test:443", checker.StatusWarning, 12, expires)}
	s.Record(s.Pending(first, now, 0), now)

	if got := s.Pending(first, now.Add(30*24*time.Hour), 0); len(got) != 0 {
		t.Fatal("with the repetition disabled an unchanged problem must stay quiet forever")
	}
}

func TestStepFor(t *testing.T) {
	cases := []struct {
		days int
		want int
	}{
		{200, 0}, // above the ladder
		{31, 0},
		{30, 30},
		{20, 30},
		{14, 14},
		{8, 14},
		{7, 7},
		{4, 7},
		{3, 3},
		{2, 3},
		{1, 1},
		{0, 1},
	}
	for _, c := range cases {
		r := checker.Result{Status: checker.StatusWarning, DaysRemaining: c.days}
		if got := StepFor(r); got != c.want {
			t.Errorf("StepFor(%d days) = %d, want %d", c.days, got, c.want)
		}
	}
}

// TestStepUsesTheChainDeadline ties the two features together: when an
// intermediate is what is running out, the ladder has to count that one.
func TestStepUsesTheChainDeadline(t *testing.T) {
	chainDays := 5
	chainExpires := time.Now().Add(5 * 24 * time.Hour)
	r := checker.Result{
		Status:             checker.StatusCritical,
		DaysRemaining:      200,
		ChainDaysRemaining: &chainDays,
		ChainExpiresAt:     &chainExpires,
	}
	if got := StepFor(r); got != 7 {
		t.Errorf("StepFor = %d, want the rung of the chain deadline (7)", got)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")

	s := New()
	s.Record([]checker.Result{result("a.test:443", checker.StatusCritical, 3, now.Add(3*24*time.Hour))}, now)
	if err := s.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	// The file lists the domains that are currently broken.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	entry, ok := loaded.Domains["a.test:443"]
	if !ok {
		t.Fatal("the entry did not survive the round trip")
	}
	if entry.Status != checker.StatusCritical || entry.Step != 3 || !entry.NotifiedAt.Equal(now) {
		t.Errorf("entry = %+v", entry)
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing state file must not be an error: %v", err)
	}
	if len(s.Domains) != 0 {
		t.Errorf("the state should be empty, got %+v", s.Domains)
	}
}

// TestLoadCorruptFileFailsOpen: a broken state file must never be able to
// silence the alerts.
func TestLoadCorruptFileFailsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	s, err := Load(path)
	if err == nil {
		t.Error("a corrupt file should be reported")
	}
	if s == nil || s.Domains == nil {
		t.Fatal("Load must still return a usable state")
	}

	now := time.Now()
	got := s.Pending([]checker.Result{result("a.test:443", checker.StatusCritical, 3, now.Add(72*time.Hour))}, now, DefaultRepeatAfter)
	if len(got) != 1 {
		t.Error("with no history everything is announced again — noisy, never silent")
	}
}
