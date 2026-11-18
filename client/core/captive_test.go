package core

// Tests of the captive portal watcher's pure logic: response classification,
// extracting the portal host from Location, filtering DNS servers.
// Unit tests — network functions are not called.

import (
	"strings"
	"testing"
	"time"
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

func TestCaptiveEntryURL(t *testing.T) {
	cases := []struct {
		url, host, want string
	}{
		{"https://portal.example.com/guest/s/x?ap=aa", "portal.example.com", "https://portal.example.com/guest/s/x?ap=aa"},
		{"  https://portal.example.com/login?a=b  ", "portal.example.com", "https://portal.example.com/login?a=b"},
		{"http://wifi.example.com:8080/login", "wifi.example.com", "http://wifi.example.com:8080/login"},
		{"", "portal.example.com", "https://portal.example.com/"},
		{"   ", "portal.example.com", "https://portal.example.com/"},
		{"garbage not a url", "portal.example.com", "https://portal.example.com/"},
		{"ftp://files.example.com/x", "portal.example.com", "https://portal.example.com/"},
		{"", "", "http://www.msftconnecttest.com/redirect"},
	}
	for _, tc := range cases {
		if got := captiveEntryURL(tc.url, tc.host); got != tc.want {
			t.Fatalf("captiveEntryURL(%q, %q) = %q, want %q", tc.url, tc.host, got, tc.want)
		}
	}
}

func TestCaptiveListContains(t *testing.T) {
	list := []string{"192.0.2.1", "192.0.2.123"}
	if !captiveListContains(list, "192.0.2.123") || captiveListContains(list, "8.8.8.8") || captiveListContains(nil, "192.0.2.4") {
		t.Fatal("captiveListContains is inconsistent")
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
}

func TestCaptiveNRPTNeeded(t *testing.T) {
	const host = "portal.example.com"
	const resolver = "192.0.2.53"
	cases := []struct {
		name string
		env  captiveResolutionEnv
		want bool
	}{
		{
			name: "global NRPT rule does not suppress exact entry rule",
			env: captiveResolutionEnv{nrptRules: []captiveNRPTRule{
				{namespace: ".", servers: []string{"127.0.0.1"}},
			}},
			want: true,
		},
		{
			name: "suffix NRPT rule does not suppress exact entry rule",
			env: captiveResolutionEnv{nrptRules: []captiveNRPTRule{
				{namespace: "example.com", servers: []string{"192.0.2.1"}},
			}},
			want: true,
		},
		{
			name: "no NRPT rules at all",
			env:  captiveResolutionEnv{},
			want: true,
		},
		{
			name: "identical rule is only a duplicate",
			env: captiveResolutionEnv{nrptRules: []captiveNRPTRule{
				{namespace: host, servers: []string{resolver}},
			}},
			want: false,
		},
		{
			name: "changed resolver replaces exact rule",
			env: captiveResolutionEnv{nrptRules: []captiveNRPTRule{
				{namespace: host, servers: []string{"192.0.2.54"}},
			}},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := captiveNRPTNeeded(host, resolver, tc.env); got != tc.want {
				t.Fatalf("captiveNRPTNeeded() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseInterfaceDNSConfig(t *testing.T) {
	cfg, err := parseInterfaceDNSConfig([]byte(`{"source":"dhcp","servers":["192.0.2.1","198.51.100.1","203.0.113.1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.source != "dhcp" || len(cfg.servers) != 3 || cfg.servers[0] != "192.0.2.1" {
		t.Fatalf("DHCP config = %+v, want source=dhcp and all three servers", cfg)
	}
	cfg, err = parseInterfaceDNSConfig([]byte(`{"source":"static","servers":["192.0.2.10"]}`))
	if err != nil || cfg.source != "static" || len(cfg.servers) != 1 {
		t.Fatalf("static config = %+v, err=%v", cfg, err)
	}
	cfg, err = parseInterfaceDNSConfig([]byte(`{"source":"dhcp","servers":[]}`))
	if err != nil || cfg.source != "dhcp" || len(cfg.servers) != 0 {
		t.Fatalf("empty DHCP config = %+v, err=%v", cfg, err)
	}
	if _, err := parseInterfaceDNSConfig([]byte(`{"source":"other","servers":[]}`)); err == nil {
		t.Fatal("unknown DNS source accepted")
	}
}

func TestCaptiveUnknownRetry(t *testing.T) {
	if delay, ok := captiveUnknownRetry(1); !ok || delay != 5*time.Second {
		t.Fatalf("attempt 1 = %v, %v; want 5s, true", delay, ok)
	}
	if delay, ok := captiveUnknownRetry(2); !ok || delay != 10*time.Second {
		t.Fatalf("attempt 2 = %v, %v; want 10s, true", delay, ok)
	}
	if delay, ok := captiveUnknownRetry(3); ok || delay != 0 {
		t.Fatalf("attempt 3 = %v, %v; want final pause", delay, ok)
	}
}

func TestCaptiveUnknownDoesNotSetLastProbeOrCrossGeneration(t *testing.T) {
	cw := &captiveWatcher{
		gw:         "192.0.2.1",
		iface:      "test0",
		generation: 7,
		stopCh:     make(chan struct{}),
	}
	cw.recordUnknown(cw.gw, cw.iface, 7)
	if !cw.lastProbe.IsZero() || cw.unknownTry != 1 || cw.probePaused {
		t.Fatalf("first unknown state: lastProbe=%v attempts=%d paused=%v", cw.lastProbe, cw.unknownTry, cw.probePaused)
	}
	cw.generation++
	cw.recordUnknown(cw.gw, cw.iface, 7)
	if cw.unknownTry != 1 {
		t.Fatalf("stale verdict changed attempts to %d", cw.unknownTry)
	}
}

func TestCaptiveFinishOpenRequiresTwoConsecutiveAliveTicks(t *testing.T) {
	cw := &captiveWatcher{probePaused: true}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("first alive action = %v, want wait", action)
	}
	if action := cw.observeTunnelLocked(false); action != captiveTunnelContinue {
		t.Fatalf("dead tick action = %v, want continue", action)
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("alive after reset action = %v, want wait", action)
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelFinishOpen {
		t.Fatalf("second consecutive alive action = %v, want finishOpen", action)
	}
	if cw.aliveTicks != 0 || cw.deadTicks != 0 {
		t.Fatalf("finishOpen left streaks alive=%d dead=%d", cw.aliveTicks, cw.deadTicks)
	}
}

func TestCaptiveStaleLivenessNotTrustedUntilDeadTick(t *testing.T) {
	// Живые тики сразу после смены сети — возможно, хвост сессий прежней сети;
	// они не дают finishOpen, пока живость не подтверждена мёртвым тиком.
	cw := &captiveWatcher{probePaused: true}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("alive before any dead tick = %v, want wait (untrusted)", action)
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("second alive still untrusted = %v, want wait", action)
	}
	if cw.aliveTicks != 0 {
		t.Fatalf("untrusted alive ticks leaked into streak: %d", cw.aliveTicks)
	}
	if action := cw.observeTunnelLocked(false); action != captiveTunnelContinue {
		t.Fatalf("dead tick = %v, want continue", action)
	}
	if !cw.aliveTrusted {
		t.Fatal("dead tick did not establish liveness trust")
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("first trusted alive = %v, want wait", action)
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelFinishOpen {
		t.Fatalf("second trusted alive = %v, want finishOpen", action)
	}
}

func TestCaptiveNetworkChangeResetsLivenessTrust(t *testing.T) {
	cw := &captiveWatcher{gw: "192.0.2.1", iface: "eth", aliveTrusted: true}
	cw.changeNetwork("192.0.2.9", "eth", false)
	if cw.aliveTrusted {
		t.Fatal("network change did not reset liveness trust")
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("alive after network change = %v, want wait (stale workers)", action)
	}
}

func TestCaptiveOpenNetworkRecapturesAfterThreeDeadTicks(t *testing.T) {
	cw := &captiveWatcher{
		openKnown:   true,
		probePaused: true,
		nextProbe:   time.Now().Add(time.Hour),
		unknownTry:  2,
	}
	for tick := 1; tick < captiveOpenDeadTicks; tick++ {
		if action := cw.observeTunnelLocked(false); action != captiveTunnelMaintainOpen {
			t.Fatalf("dead tick %d action = %v, want maintainOpen", tick, action)
		}
		if !cw.openKnown || !cw.probePaused {
			t.Fatalf("dead tick %d reopened state too early", tick)
		}
	}
	if action := cw.observeTunnelLocked(false); action != captiveTunnelRecapture {
		t.Fatalf("third dead tick action = %v, want recapture", action)
	}
	if cw.openKnown || cw.probePaused || !cw.nextProbe.IsZero() || cw.unknownTry != 0 {
		t.Fatalf("recapture state = open=%v paused=%v next=%v attempts=%d",
			cw.openKnown, cw.probePaused, cw.nextProbe, cw.unknownTry)
	}
	if cw.deadTicks != 0 {
		t.Fatalf("recapture left dead streak %d", cw.deadTicks)
	}

	// Reopened state still requires two live ticks before finishOpen.
	if action := cw.observeTunnelLocked(true); action != captiveTunnelWait {
		t.Fatalf("first alive after recapture = %v, want wait", action)
	}
	if action := cw.observeTunnelLocked(true); action != captiveTunnelFinishOpen {
		t.Fatalf("second alive after recapture = %v, want finishOpen", action)
	}
}

func TestCaptiveOpenDeadStreakResetsOnAliveTick(t *testing.T) {
	cw := &captiveWatcher{openKnown: true, probePaused: true}
	cw.observeTunnelLocked(false)
	cw.observeTunnelLocked(false)
	if action := cw.observeTunnelLocked(true); action != captiveTunnelMaintainOpen {
		t.Fatalf("alive tick action = %v, want maintainOpen", action)
	}
	if cw.deadTicks != 0 {
		t.Fatalf("alive tick did not reset dead streak: %d", cw.deadTicks)
	}
	for tick := 1; tick < captiveOpenDeadTicks; tick++ {
		if action := cw.observeTunnelLocked(false); action != captiveTunnelMaintainOpen {
			t.Fatalf("new dead streak tick %d action = %v", tick, action)
		}
	}
	if action := cw.observeTunnelLocked(false); action != captiveTunnelRecapture {
		t.Fatalf("new third dead tick action = %v, want recapture", action)
	}
}

func TestLoopbackOnlyDNSCaptureRejected(t *testing.T) {
	for _, cfg := range []interfaceDNSConfig{
		{source: "static", servers: []string{"127.0.0.1"}},
		{source: "dhcp", servers: []string{"::1"}},
	} {
		if !loopbackOnlyDNS(cfg) {
			t.Fatalf("loopbackOnlyDNS(%+v) = false", cfg)
		}
	}
	for _, cfg := range []interfaceDNSConfig{
		{source: "static", servers: []string{"192.0.2.53"}},
		{source: "static", servers: []string{"127.0.0.1", "192.0.2.53"}},
		{source: "dhcp", servers: nil},
	} {
		if loopbackOnlyDNS(cfg) {
			t.Fatalf("loopbackOnlyDNS(%+v) = true", cfg)
		}
	}
}

func TestCaptivePortalLaunchRejectsStaleGeneration(t *testing.T) {
	cw := &captiveWatcher{
		gw: "192.0.2.1", iface: "test0", generation: 4,
		active: true, stopCh: make(chan struct{}),
	}
	if !cw.portalLaunchCurrent(cw.gw, cw.iface, 4) {
		t.Fatal("current portal launch rejected")
	}
	if cw.portalLaunchCurrent(cw.gw, cw.iface, 3) {
		t.Fatal("stale portal launch accepted")
	}
	cw.active = false
	if cw.portalLaunchCurrent(cw.gw, cw.iface, 4) {
		t.Fatal("inactive portal launch accepted")
	}
}

func TestStopCaptiveWatcherDoesNotWaitForInflightProbe(t *testing.T) {
	cw := &captiveWatcher{
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}), // deliberately never closed: probe is still in flight
		routes:    make(map[string]bool),
		nrptRules: make(map[string]string),
	}
	captiveMu.Lock()
	previous := activeCaptive
	activeCaptive = cw
	captiveMu.Unlock()
	defer func() {
		captiveMu.Lock()
		activeCaptive = previous
		captiveMu.Unlock()
	}()

	returned := make(chan struct{})
	go func() {
		StopCaptiveWatcher()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("StopCaptiveWatcher waited for doneCh")
	}
	select {
	case <-cw.stopCh:
	default:
		t.Fatal("watcher stop channel was not closed")
	}
	if current := currentCaptiveWatcher(); current != nil {
		t.Fatalf("watcher still registered: %p", current)
	}
}
