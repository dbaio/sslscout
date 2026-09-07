package checker

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

// TestChainExpiry covers the failure AddTrust and DST Root X3 made famous: the
// leaf is nowhere near expiring, and the site goes down anyway because the
// intermediate under it ran out first.
func TestChainExpiry(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	leaf := certificate(t, now.Add(-24*time.Hour), now.Add(200*24*time.Hour), "example.test")

	cases := []struct {
		name       string
		chain      []*x509.Certificate
		wantStatus Status
		wantDays   int  // effective deadline
		wantChain  bool // the chain_* fields are expected
	}{
		{
			name:       "leaf alone",
			chain:      nil,
			wantStatus: StatusOK,
			wantDays:   200,
		},
		{
			name:       "intermediate outliving the leaf",
			chain:      []*x509.Certificate{certificate(t, now, now.Add(900*24*time.Hour), "Intermediate CA")},
			wantStatus: StatusOK,
			wantDays:   200,
		},
		{
			name:       "intermediate expiring first",
			chain:      []*x509.Certificate{certificate(t, now, now.Add(4*24*time.Hour), "Intermediate CA")},
			wantStatus: StatusCritical,
			wantDays:   4,
			wantChain:  true,
		},
		{
			name: "the earliest of two intermediates wins",
			chain: []*x509.Certificate{
				certificate(t, now, now.Add(30*24*time.Hour), "Intermediate CA"),
				certificate(t, now, now.Add(10*24*time.Hour), "Cross-signing CA"),
			},
			wantStatus: StatusWarning,
			wantDays:   10,
			wantChain:  true,
		},
		{
			// Servers pad the chain with the root out of habit. Trust comes
			// from the local store, whose copy has its own dates, so the one on
			// the wire must not drive an alert.
			name:       "a self-signed root is ignored",
			chain:      []*x509.Certificate{mustSelfSigned(t, "Old Root CA", now, now.Add(3*24*time.Hour))},
			wantStatus: StatusOK,
			wantDays:   200,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := tls.ConnectionState{
				Version:          tls.VersionTLS13,
				PeerCertificates: append([]*x509.Certificate{leaf}, c.chain...),
			}

			var r Result
			r.applyCertificate(state, testOptions(now))

			if r.Status != c.wantStatus {
				t.Errorf("status = %q, want %q", r.Status, c.wantStatus)
			}
			if got := r.EffectiveDaysRemaining(); got != c.wantDays {
				t.Errorf("effective days = %d, want %d", got, c.wantDays)
			}
			// The leaf's own countdown is never overwritten: the report has to
			// keep saying what the certificate itself says.
			if r.DaysRemaining != 200 {
				t.Errorf("days_remaining = %d, want the leaf's 200", r.DaysRemaining)
			}

			if !c.wantChain {
				if r.ChainExpiresAt != nil || r.ChainDaysRemaining != nil || r.ChainSubject != "" {
					t.Errorf("the chain fields should be absent, got %+v / %v / %q",
						r.ChainExpiresAt, r.ChainDaysRemaining, r.ChainSubject)
				}
				return
			}
			if r.ChainExpiresAt == nil || r.ChainDaysRemaining == nil {
				t.Fatal("the chain fields should be filled in")
			}
			if *r.ChainDaysRemaining != c.wantDays {
				t.Errorf("chain_days_remaining = %d, want %d", *r.ChainDaysRemaining, c.wantDays)
			}
			if r.ChainSubject == "" {
				t.Error("chain_subject should name the certificate that expires first")
			}
		})
	}
}

func mustSelfSigned(t *testing.T, name string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	cert, _ := selfSigned(t, name, notBefore, notAfter)
	return cert
}
