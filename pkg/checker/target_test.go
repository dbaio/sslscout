package checker

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		host    string
		port    int
		wantsOK bool
	}{
		{"bare host", "google.com", "google.com", 443, true},
		{"host with port", "smtp.example.com:465", "smtp.example.com", 465, true},
		{"uppercase becomes lowercase", "GitHub.COM", "github.com", 443, true},
		{"trailing dot removed", "example.com.", "example.com", 443, true},
		{"surrounding spaces", "  example.com  ", "example.com", 443, true},
		{"https url", "https://example.com/path", "example.com", 443, true},
		{"https url with port", "https://example.com:8443/x?y=1", "example.com", 8443, true},
		{"http url becomes 443", "http://example.com", "example.com", 443, true},
		{"ldaps url uses the scheme port", "ldaps://ldap.example.com", "ldap.example.com", 636, true},
		{"ipv4", "127.0.0.1:8443", "127.0.0.1", 8443, true},
		{"ipv6 with port", "[::1]:443", "::1", 443, true},
		{"ipv6 without port", "2001:db8::1", "2001:db8::1", 443, true},
		{"empty", "", "", 0, false},
		{"non numeric port", "example.com:abc", "", 0, false},
		{"port zero", "example.com:0", "", 0, false},
		{"port above the limit", "example.com:70000", "", 0, false},
		{"port missing after the colon", "example.com:", "", 0, false},
		{"host with a slash", "exa/mple.com", "", 0, false},
		{"url without host", "https:///path", "", 0, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, err := ParseTarget(c.input)
			if c.wantsOK && err != nil {
				t.Fatalf("ParseTarget(%q) returned an unexpected error: %v", c.input, err)
			}
			if !c.wantsOK {
				if err == nil {
					t.Fatalf("ParseTarget(%q) should have failed, returned %v", c.input, target)
				}
				return
			}
			if target.Host != c.host || target.Port != c.port {
				t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d",
					c.input, target.Host, target.Port, c.host, c.port)
			}
		})
	}
}

func TestTargetString(t *testing.T) {
	cases := []struct {
		target Target
		want   string
	}{
		{Target{"example.com", 443}, "example.com:443"},
		{Target{"::1", 8443}, "[::1]:8443"},
	}
	for _, c := range cases {
		if got := c.target.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}

func TestParseTargetList(t *testing.T) {
	input := strings.Join([]string{
		"# Domain list",
		"",
		"google.com",
		"github.com   # trailing comment",
		"google.com",     // literal duplicate
		"google.com:443", // duplicate after normalization
		"GOOGLE.COM",     // duplicate after lowercasing
		"https://example.com/status",
		"example.com:8443",
		"   ",
		"#comment only",
	}, "\n")

	targets, err := ParseTargetList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"google.com:443",
		"github.com:443",
		"example.com:443",
		"example.com:8443",
	}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets (%v), want %d", len(targets), targets, len(want))
	}
	for i, w := range want {
		if targets[i].String() != w {
			t.Errorf("target[%d] = %q, want %q (the original order must be preserved)",
				i, targets[i].String(), w)
		}
	}
}

func TestParseTargetListReportsInvalidLines(t *testing.T) {
	input := "good.example.com\nexample.com:abc\nother.example.com\nhttps://\n"

	targets, err := ParseTargetList(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected an aggregated error for the invalid lines")
	}
	if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 4") {
		t.Errorf("the error should point at lines 2 and 4, got: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("the valid lines should be kept, got %v", targets)
	}
}

// brokenReader simulates an I/O error halfway through the file: the old bug was
// that scanner.Err() was never checked, silently truncating the list.
type brokenReader struct{ read bool }

func (r *brokenReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, errors.New("the disk caught fire")
	}
	r.read = true
	n := copy(p, "example.com\n")
	return n, nil
}

func TestParseTargetListPropagatesReadError(t *testing.T) {
	targets, err := ParseTargetList(&brokenReader{})
	if err == nil {
		t.Fatal("a read error must be propagated, not swallowed")
	}
	if !strings.Contains(err.Error(), "the disk caught fire") {
		t.Errorf("the original error should be wrapped, got: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("targets read before the failure should come back, got %v", targets)
	}
}

func TestParseTargetListIgnoresBOM(t *testing.T) {
	targets, err := ParseTargetList(strings.NewReader("\ufeffexample.com\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "example.com" {
		t.Errorf("the BOM should be ignored, got %v", targets)
	}
}
