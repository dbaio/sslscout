// Package state remembers what has already been announced, so that a check
// running every hour does not send the same alert every hour.
//
// A stateless checker on a cron has one failure mode that outweighs any missing
// feature: with alert_threshold_days at 15 and an hourly schedule, one
// expiring certificate produces around 360 identical messages before anybody
// renews it. Nobody responds to that by fixing the certificate faster. They
// mute the channel — and then they miss the next outage, which is the one the
// tool existed for.
//
// The rules are few on purpose, and every one of them can only suppress a
// repeat of something already sent:
//
//   - a domain nobody has heard about yet always alerts;
//   - a change of status always alerts (warning to critical, invalid to error);
//   - a replaced certificate always alerts, because a renewal that is still
//     wrong is news;
//   - crossing a rung of the ladder (30, 14, 7, 3, 1 days) always alerts;
//   - anything else repeats only once per RepeatAfter, 24h by default.
//
// When the answer is unclear the tool sends: a duplicate alert is an
// annoyance, a swallowed one is an outage.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dbaio/sslscout/pkg/checker"
)

// SchemaVersion of the state file written by this package.
const SchemaVersion = 1

// DefaultRepeatAfter is how long an unchanged problem stays quiet.
const DefaultRepeatAfter = 24 * time.Hour

// Steps is the ladder of day counts that always earn a fresh alert. Crossing
// one is news even when the status has not moved: "14 days" and "7 days" are
// different conversations with whoever owns the certificate.
var Steps = []int{30, 14, 7, 3, 1}

// Entry is what was last announced for one domain.
type Entry struct {
	Status checker.Status `json:"status"`
	// Step is the rung the countdown had reached. Zero means "above the top
	// rung", which is also what non-countdown statuses (error, invalid) store.
	Step int `json:"step,omitempty"`
	// ExpiresAt detects replacement: a different expiry date means a different
	// certificate, and the alert about the old one no longer applies.
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	NotifiedAt time.Time  `json:"notified_at"`
}

// State is the whole file: what has been announced, keyed by domain.
type State struct {
	SchemaVersion int              `json:"schema_version"`
	UpdatedAt     time.Time        `json:"updated_at"`
	Domains       map[string]Entry `json:"domains"`
}

// New returns an empty state.
func New() *State {
	return &State{SchemaVersion: SchemaVersion, Domains: map[string]Entry{}}
}

// Load reads the state file.
//
// A missing file is not an error: the first run of a new install has no
// history. A corrupt one is reported, but still yields a usable empty state —
// the caller is expected to log the problem and carry on alerting, because the
// alternative is a broken file quietly silencing every notification.
func Load(path string) (*State, error) {
	s := New()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, fmt.Errorf("could not read the state file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, s); err != nil {
		return New(), fmt.Errorf("invalid state in %s (starting from scratch): %w", path, err)
	}
	if s.Domains == nil {
		s.Domains = map[string]Entry{}
	}
	return s, nil
}

// Pending selects the results worth announcing now.
//
// It has no side effects, and that is the point: Record runs only once the
// alert has actually gone out, so a webhook that was down costs a retry on the
// next run instead of a lost notification.
func (s *State) Pending(results []checker.Result, now time.Time, repeatAfter time.Duration) []checker.Result {
	var pending []checker.Result
	for _, r := range results {
		if r.Status == checker.StatusOK {
			continue
		}
		if s.shouldNotify(r, now, repeatAfter) {
			pending = append(pending, r)
		}
	}
	return pending
}

func (s *State) shouldNotify(r checker.Result, now time.Time, repeatAfter time.Duration) bool {
	prev, seen := s.Domains[r.Domain]
	switch {
	case !seen:
		return true
	case prev.Status != r.Status:
		return true
	case !sameCertificate(prev.ExpiresAt, r.ExpiresAt):
		return true
	case descended(prev.Step, StepFor(r)):
		return true
	case repeatAfter <= 0:
		// Repetition disabled: only a real change gets through from here on.
		return false
	default:
		return !now.Before(prev.NotifiedAt.Add(repeatAfter))
	}
}

// Record marks the given results as announced at now. Results that are ok are
// ignored: Sync is what clears them.
func (s *State) Record(results []checker.Result, now time.Time) {
	for _, r := range results {
		if r.Status == checker.StatusOK {
			continue
		}
		entry := Entry{
			Status:     r.Status,
			Step:       StepFor(r),
			NotifiedAt: now.UTC(),
		}
		if r.ExpiresAt != nil {
			// Copied, not aliased: the state outlives the report it came from.
			expires := *r.ExpiresAt
			entry.ExpiresAt = &expires
		}
		s.Domains[r.Domain] = entry
	}
	s.UpdatedAt = now.UTC()
}

// Sync forgets the domains that no longer need remembering: the ones that came
// back to ok, so the next problem alerts immediately, and the ones that left
// domains.txt, so the file does not grow forever.
//
// It must only be called with the results of a complete run. Handed a partial
// list — an interrupted check, say — it would forget domains that were merely
// never reached.
func (s *State) Sync(results []checker.Result, now time.Time) {
	current := make(map[string]checker.Status, len(results))
	for _, r := range results {
		current[r.Domain] = r.Status
	}
	for domain := range s.Domains {
		if status, still := current[domain]; !still || status == checker.StatusOK {
			delete(s.Domains, domain)
		}
	}
	s.UpdatedAt = now.UTC()
}

// StepFor returns the rung of the ladder a result sits on: the lowest step that
// still covers its deadline. Zero means it is above the top rung, and is also
// what the statuses with no countdown (error, invalid, expired) report.
func StepFor(r checker.Result) int {
	if !r.Status.Valid() {
		return 0
	}
	days := r.EffectiveDaysRemaining()
	step := 0
	for _, s := range Steps {
		if days <= s && (step == 0 || s < step) {
			step = s
		}
	}
	return step
}

// descended reports whether the countdown moved down a rung. Zero is the
// position above the whole ladder, so entering it from zero counts.
func descended(prev, cur int) bool {
	switch {
	case cur == 0:
		return false
	case prev == 0:
		return true
	default:
		return cur < prev
	}
}

func sameCertificate(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// Save writes the state atomically, with 0600.
//
// The permissions are not paranoia: this file lists every domain that currently
// has a problem, which is the same inventory that keeps domains.txt out of Git.
func (s *State) Save(path string) error {
	s.SchemaVersion = SchemaVersion
	if s.Domains == nil {
		s.Domains = map[string]Entry{}
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("could not serialize the state: %w", err)
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
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("could not set the permissions of %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("could not publish the state to %s: %w", path, err)
	}
	return nil
}
