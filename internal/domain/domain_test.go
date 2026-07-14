package domain

import (
	"strings"
	"testing"
)

func TestURN(t *testing.T) {
	cases := []struct {
		homeDomain string
		agentName  string
		want       string
	}{
		{"tessera.example.org", "seneca", "urn:tessera:tessera.example.org:seneca"},
		{"athena-council.org", "aurora", "urn:tessera:athena-council.org:aurora"},
		{"localhost", "test-agent", "urn:tessera:localhost:test-agent"},
	}
	for _, tc := range cases {
		got := URN(tc.homeDomain, tc.agentName)
		if got != tc.want {
			t.Errorf("URN(%q, %q) = %q, want %q", tc.homeDomain, tc.agentName, got, tc.want)
		}
	}
}

func TestURNPrefix(t *testing.T) {
	urn := URN("example.com", "myagent")
	if !strings.HasPrefix(urn, "urn:tessera:") {
		t.Errorf("URN %q does not start with urn:tessera:", urn)
	}
}

func TestURNContainsBothParts(t *testing.T) {
	domain := "example.com"
	name := "myagent"
	urn := URN(domain, name)
	if !strings.Contains(urn, domain) {
		t.Errorf("URN %q does not contain domain %q", urn, domain)
	}
	if !strings.Contains(urn, name) {
		t.Errorf("URN %q does not contain agent name %q", urn, name)
	}
}
