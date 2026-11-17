package core

// Tests of the captive portal watcher's pure logic: response classification,
// extracting the portal host from Location, filtering DNS servers.
// Unit tests — network functions are not called.

import (
	"strings"
	"testing"
)

func TestClassifyCaptiveProbe(t *testing.T) {
	const ncsi = "Microsoft Connect Test"
	cases := []struct {
		name     string
		status   int
		body     string
		location string
		marker   string
		verdict  captiveVerdict
		portal   string
	}{
		{"ncsi ok", 200, ncsi, "", ncsi, captiveOpen, ""},
		{"ncsi hijacked", 200, "<html>login</html>", "", ncsi, captivePortal, ""},
		{"ncsi 500", 500, "", "", ncsi, captiveUnknown, ""},
		{"204 ok", 204, "", "", "", captiveOpen, ""},
		{"204 hijacked", 200, "<html>wifi</html>", "", "", captivePortal, ""},
		{"204 wrong for ncsi", 204, "", "", ncsi, captiveUnknown, ""},
		{"redirect to portal", 302, "", "https://portal.example.com/auth?x=1", ncsi, captivePortal, "portal.example.com"},
		{"redirect with port", 302, "", "http://wifi.example.com:8080/login", "", captivePortal, "wifi.example.com"},
		{"redirect garbage", 302, "", "not a url", "", captivePortal, ""},
		{"redirect no scheme", 302, "", "//portal.example.com/", "", captivePortal, ""},
		{"redirect ip", 302, "", "http://10.20.30.40/portal", "", captivePortal, ""},
		{"temp redirect", 307, "", "https://auth.example.net/start", "", captivePortal, "auth.example.net"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, host := classifyCaptiveProbe(tc.status, []byte(tc.body), tc.location, tc.marker)
			if v != tc.verdict || host != tc.portal {
				t.Fatalf("classify(%d, %q, %q, %q) = (%v, %q), want (%v, %q)",
					tc.status, tc.body, tc.location, tc.marker, v, host, tc.verdict, tc.portal)
			}
		})
	}
}

func TestExtractPortalHost(t *testing.T) {
	cases := []struct {
		location string
		want     string
	}{
		{"https://portal.example.com/auth?a=b&mac=aa", "portal.example.com"},
		{"HTTP://Portal.Example.COM:8080/login", "portal.example.com"},
		{"http://portal.example.com./x", "portal.example.com"},
		{"http://10.20.30.40/portal", ""},
		{"ftp://portal.example.com/", ""},
		{"//portal.example.com/", ""},
		{"", ""},
		{"   ", ""},
		{"http://singlelabel/", ""},
		{"http://a..b.example.com/", ""},
		{"https://" + strings.Repeat("a", 250) + ".com/", ""},
	}
	for _, tc := range cases {
		if got := extractPortalHost(tc.location); got != tc.want {
			t.Fatalf("extractPortalHost(%q) = %q, want %q", tc.location, got, tc.want)
		}
	}
}

func TestValidCaptiveHost(t *testing.T) {
	valid := []string{"portal.example.com", "wifi-new.example.com", "a.b.c.example.com", "192.168.76.example"}
	for _, h := range valid {
		if !validCaptiveHost(h) {
			t.Fatalf("validCaptiveHost(%q) = false, want true", h)
		}
	}
	invalid := []string{
		"", "portal", "portal.example.com.", "a..b.com", "Portal.example.com",
		"10.20.30.40", "host_name.example.com", "portal.example.com/path",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 64) + ".com",
	}
	for _, h := range invalid {
		if validCaptiveHost(h) {
			t.Fatalf("validCaptiveHost(%q) = true, want false", h)
		}
	}
}

func TestSanitizeDNSServers(t *testing.T) {
	orig := []string{"127.0.0.1", "10.0.0.1", "8.8.8.8", "not-an-ip", "fe80::1"}
	got := sanitizeDNSServers(orig, "192.168.1.1")
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "8.8.8.8" {
		t.Fatalf("sanitizeDNSServers = %v, want [10.0.0.1 8.8.8.8]", got)
	}
	if got := sanitizeDNSServers([]string{"127.0.0.1"}, "192.168.1.1"); len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("sanitizeDNSServers = %v, want [192.168.1.1] (gateway fallback)", got)
	}
	if got := sanitizeDNSServers(nil, ""); len(got) != 0 {
		t.Fatalf("sanitizeDNSServers(nil, \"\") = %v, want empty", got)
	}
}

func TestCaptiveProbeTargetsInit(t *testing.T) {
	if len(captiveProbeTargets) == 0 {
		t.Fatal("no probe targets")
	}
	for _, tgt := range captiveProbeTargets {
		if tgt.host == "" || !validCaptiveHost(tgt.host) {
			t.Fatalf("probe target %q: bad host %q", tgt.url, tgt.host)
		}
	}
	if !captiveAllowName("www.msftconnecttest.com") || captiveAllowName("portal.example.com") {
		t.Fatal("captiveAllowName is inconsistent")
	}
}
