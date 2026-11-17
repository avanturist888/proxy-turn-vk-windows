package core

// Captive portals (guest Wi-Fi with an authorization page).
//
// Until the portal is authorized, the tunnel cannot come up: the portal suppresses
// someone else's traffic and substitutes TLS (VK/TURN are unreachable), and the DNS
// override to the local proxy makes system resolution dependent on the dead tunnel —
// the browser does not resolve even the portal's own page. We get a circle:
// the tunnel waits for the internet, the internet waits for authorization,
// authorization waits for DNS, DNS waits for the tunnel.
//
// The watcher breaks the circle without any hardcoding of specific portals:
//   1. It checks the network with standard plain-HTTP probes (NCSI and generate_204)
//      directly through the physical gateway — a captive portal gives itself away
//      by a redirect to its page or by a substitution page.
//   2. In captive mode, it lets through past the tunnel only:
//        - the probe hosts themselves (Windows NCSI sees the portal and the moment
//          authorization finishes);
//        - the portal host extracted from the probe redirect (no hardcoded lists);
//      everything else continues to be routed into the tunnel (0.0.0.0/0) and is
//      discarded — no "free internet" through a hostile network with TLS substitution.
//   3. So that these names are resolved by system DNS — NRPT rules pointing to the
//      network's DHCP DNS (they are more specific than catch-all rules and other
//      NRPT policies; removed upon exiting captive mode).
//
// After authorization, the probe starts answering as expected — the rules are removed,
// and the tunnel comes back via the usual reconnect mechanism (worker retries
// and the orchestrator's backoff).

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// Tag of NRPT rules: removal looks for rules by it, so that after a crash
	// no left-over rules for the portal remain in the system.
	captiveNRPTTag = "wdtt-captive"

	// Frequency of re-checks in captive mode: after authorization we must notice
	// the released network quickly and let the tunnel come up.
	captiveProbeEvery = 10 * time.Second

	captiveHTTPTimeout = 5 * time.Second
)

// captiveProbeTarget — a check "is there internet beyond the gateway".
// Only plain HTTP: interception shows itself as a redirect or a substitution page;
// over HTTPS it would look like a certificate error and would not reveal the portal.
var captiveProbeTargets = []struct {
	url    string
	marker string // "" — expecting HTTP 204 and an empty body
	host   string // filled in init
}{
	// The same probe as Windows NCSI: on a free network — 200 with this body.
	{url: "http://www.msftconnecttest.com/connecttest.txt", marker: "Microsoft Connect Test"},
	// Backup: 204 with an empty body.
	{url: "http://www.gstatic.com/generate_204", marker: ""},
}

// Names allowed past the tunnel in captive mode: probe hosts (so that Windows NCSI
// works on the captive network and sees the end of authorization) + DNS part of NCSI.
// The portal host, if it could be extracted from the redirect, is added to them on the fly.
var captiveAllowNames = []string{"www.msftconnecttest.com", "dns.msftncsi.com", "www.gstatic.com"}

func init() {
	for i := range captiveProbeTargets {
		u, err := url.Parse(captiveProbeTargets[i].url)
		if err != nil || u.Hostname() == "" {
			panic(fmt.Sprintf("captive: bad probe url %q", captiveProbeTargets[i].url))
		}
		captiveProbeTargets[i].host = strings.ToLower(u.Hostname())
	}
}

// ─── Response classification (pure logic, covered by tests) ─────────────────

type captiveVerdict int

const (
	captiveUnknown captiveVerdict = iota // network does not answer — portal not confirmed
	captiveOpen                          // probe answered as expected — there is internet
	captivePortal                        // probe intercepted — captive portal
)

// classifyCaptiveProbe makes a verdict from an HTTP response:
//   - redirect → captive, portal host is extracted from Location;
//   - 200 with the expected marker (or 204 for marker="") → open network;
//   - 200 with the wrong body → captive (hijack without a parseable redirect).
//
// Returns the portal host (possibly empty — then only the probe hosts are allowed).
func classifyCaptiveProbe(statusCode int, body []byte, location, marker string) (captiveVerdict, string) {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return captivePortal, extractPortalHost(location)
	case 204:
		if marker == "" {
			return captiveOpen, ""
		}
		return captiveUnknown, ""
	case 200:
		if marker == "" {
			// generate_204 answered 200 — the page was substituted.
			return captivePortal, ""
		}
		if bytes.Contains(body, []byte(marker)) {
			return captiveOpen, ""
		}
		return captivePortal, ""
	default:
		return captiveUnknown, ""
	}
}

// extractPortalHost pulls the portal host from the Location header of the redirect.
// Returns "" if the address cannot be used as an NRPT rule (garbage, not http/https, IP literal).
func extractPortalHost(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if !validCaptiveHost(host) {
		return ""
	}
	return host
}

// validCaptiveHost — a host suitable for an NRPT rule: FQDN of letters/digits/hyphens,
// no empty or overly long labels, without a trailing dot. An IP literal is not suitable
// (a rule is pointless for it; access to a portal by IP is already handled by /32 routes).
func validCaptiveHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// sanitizeDNSServers filters out the useless and the hazardous: loopback (the proxy
// itself) and non-IP addresses. If nothing is left — the gateway, on most guest
// networks, doubles as a DNS server.
func sanitizeDNSServers(orig []string, gateway string) []string {
	var out []string
	for _, s := range orig {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip.To4() == nil {
			continue // NRPT NameServers and routes — IPv4 only
		}
		out = append(out, s)
	}
	if len(out) == 0 && gateway != "" && net.ParseIP(gateway) != nil {
		out = []string{gateway}
	}
	return out
}

// ─── Watcher ────────────────────────────────────────────────────────────────────

type captiveWatcher struct {
	mu         sync.Mutex
	gw         string
	iface      string
	active     bool
	probing    bool
	lastProbe  time.Time // IsZero() = probe has not happened yet → probe on the next tick
	portalHost string
	routes     map[string]bool // added /32 via the gateway (probe, DNS, portal)
	nrptDone   bool
	stopCh     chan struct{}
}

var (
	captiveMu     sync.Mutex
	activeCaptive *captiveWatcher
)

// startCaptiveWatch runs the watcher after the tunnel comes up. The first probe
// happens on the route guard's next tick (~3 s).
func startCaptiveWatch() {
	captiveMu.Lock()
	defer captiveMu.Unlock()
	if activeCaptive != nil {
		return
	}
	activeCaptive = &captiveWatcher{
		routes: make(map[string]bool),
		stopCh: make(chan struct{}),
	}
}

// stopCaptiveWatch removes the allow rules and stops the watcher.
// An in-flight probe sees the closed channel and does not apply its result.
func stopCaptiveWatch() {
	captiveMu.Lock()
	cw := activeCaptive
	activeCaptive = nil
	captiveMu.Unlock()
	if cw == nil {
		return
	}
	cw.mu.Lock()
	close(cw.stopCh)
	cw.mu.Unlock()
	cw.clearAllow()
}

func currentCaptiveWatcher() *captiveWatcher {
	captiveMu.Lock()
	defer captiveMu.Unlock()
	return activeCaptive
}

func (cw *captiveWatcher) stoppedLocked() bool {
	select {
	case <-cw.stopCh:
		return true
	default:
		return false
	}
}

// captiveTick is called from the route guard on every tick (network may have changed).
// Probe schedule: the first one — immediately after start, after a network change —
// immediately, in captive mode — every captiveProbeEvery, on a healthy network — no
// periodic probes (the tunnel is handled by its own mechanisms).
func captiveTick(gw, iface string) {
	cw := currentCaptiveWatcher()
	if cw == nil || gw == "" || iface == "" {
		return
	}
	cw.mu.Lock()
	if cw.stoppedLocked() {
		cw.mu.Unlock()
		return
	}
	cw.gw, cw.iface = gw, iface
	var due bool
	switch {
	case cw.probing:
		due = false
	case cw.active:
		due = time.Since(cw.lastProbe) >= captiveProbeEvery
	default:
		due = cw.lastProbe.IsZero()
	}
	if due {
		cw.probing = true
	}
	cw.mu.Unlock()
	if due {
		go cw.probe()
	}
}

// captiveNetworkChanged is called by the route guard on a gateway/interface change:
// the allow rules point to the old network — we remove them and re-probe.
func captiveNetworkChanged() {
	cw := currentCaptiveWatcher()
	if cw == nil {
		return
	}
	cw.mu.Lock()
	wasActive := cw.active
	cw.active = false
	cw.portalHost = ""
	cw.lastProbe = time.Time{} // probe on the next tick
	cw.mu.Unlock()
	if wasActive {
		log.Printf("[CAPTIVE] Network changed — allow rules removed, rechecking")
		cw.clearAllow()
	}
}

// probe — one network check. Runs in a goroutine; network operations happen
// outside the lock, the lock only guards the state.
func (cw *captiveWatcher) probe() {
	defer func() {
		cw.mu.Lock()
		cw.probing = false
		cw.mu.Unlock()
	}()

	cw.mu.Lock()
	gw, iface := cw.gw, cw.iface
	stopped := cw.stoppedLocked()
	cw.mu.Unlock()
	if stopped || gw == "" || iface == "" {
		return
	}

	verdict, portalHost := cw.runProbes(gw, iface)

	cw.mu.Lock()
	if cw.stoppedLocked() {
		cw.mu.Unlock()
		return
	}
	cw.lastProbe = time.Now()
	wasActive := cw.active
	cw.mu.Unlock()

	switch verdict {
	case captiveOpen:
		if wasActive {
			log.Printf("[CAPTIVE] Network released — internet is there, allowing the tunnel to come up")
			cw.clearAllow()
			cw.mu.Lock()
			cw.active = false
			cw.portalHost = ""
			cw.mu.Unlock()
			emitEvent(Event{Type: EventEvent, Name: "captive_cleared", Data: ""})
		}
	case captivePortal:
		cw.enterCaptive(gw, iface, portalHost, wasActive)
	default:
		// The network does not answer: the portal is not confirmed, the allow rules
		// are not needed. We keep the state; the next check is on a network change
		// or a core restart (orchestrator reconnect).
		if !wasActive {
			log.Printf("[CAPTIVE] Network beyond %s (%s) does not answer probes — no portal confirmed", gw, iface)
		}
	}
}

// runProbes goes through the probe targets until the first definitive answer.
// Adds /32 routes to the DNS servers and probe hosts via the gateway: on a healthy
// network they are removed again, in captive mode they remain as allow rules.
func (cw *captiveWatcher) runProbes(gw, iface string) (captiveVerdict, string) {
	dnsServers := captiveDNSServers(iface, gw)
	if len(dnsServers) == 0 {
		return captiveUnknown, ""
	}

	// DNS queries must also go past the tunnel.
	for _, srv := range dnsServers {
		cw.addAllowRoute(srv, gw)
	}

	for _, tgt := range captiveProbeTargets {
		ips := cw.resolveAllowed(tgt.host, dnsServers)
		if len(ips) == 0 {
			continue // the network's DNS does not answer — try the next target
		}
		status, body, location := captiveHTTPGet(tgt.url)
		if status == 0 {
			continue // probe host unreachable (no route yet, packets dropped)
		}
		v, host := classifyCaptiveProbe(status, body, location, tgt.marker)
		if v == captiveOpen {
			// The network is healthy: the routes added for the probe are not needed.
			cw.removeProbeRoutes()
			return v, host
		}
		if v == captivePortal {
			return v, host
		}
	}
	return captiveUnknown, ""
}

// enterCaptive activates captive mode: NRPT rules + routes for the probe hosts
// and the portal.
func (cw *captiveWatcher) enterCaptive(gw, iface, portalHost string, wasActive bool) {
	cw.mu.Lock()
	cw.active = true
	if portalHost != "" || cw.portalHost == "" {
		cw.portalHost = portalHost
	}
	portalHost = cw.portalHost
	cw.mu.Unlock()

	if !wasActive {
		if portalHost != "" {
			log.Printf("[CAPTIVE] Captive portal detected: %s (gateway %s via %s)", portalHost, gw, iface)
		} else {
			log.Printf("[CAPTIVE] Captive portal detected (gateway %s via %s); portal host not revealed, allowing only the probes", gw, iface)
		}
		emitEvent(Event{Type: EventEvent, Name: "captive_detected", Data: portalHost})
	}

	// The portal host: resolve via the network's DNS and add /32 routes.
	if portalHost != "" && !captiveAllowName(portalHost) {
		if ips := cw.resolveAllowed(portalHost, captiveDNSServers(iface, gw)); len(ips) == 0 {
			log.Printf("[CAPTIVE] %s: did not resolve via the network's DNS — portal page may not open", portalHost)
		}
	}

	// NRPT: system resolution of allowed names via DHCP DNS. Only meaningful
	// if we overrode the adapter DNS to the proxy; otherwise system DNS already
	// points to the network's DNS.
	if dnsOverrideActive(iface) {
		servers := captiveDNSServers(iface, gw)
		names := captiveAllowNames
		if portalHost != "" && !captiveAllowName(portalHost) {
			names = append(append([]string{}, captiveAllowNames...), portalHost)
		}
		added := 0
		for _, name := range names {
			if err := nrptAddRule(name, servers); err != nil {
				log.Printf("[CAPTIVE] NRPT rule for %s not added: %v", name, err)
				continue
			}
			added++
		}
		if added > 0 {
			cw.mu.Lock()
			cw.nrptDone = true
			cw.mu.Unlock()
			log.Printf("[CAPTIVE] NRPT rules added (%d) → DNS %v", added, servers)
		}
	}
	flushSystemDNSCache()
}

// clearAllow removes the /32 routes and NRPT rules added by captive mode.
func (cw *captiveWatcher) clearAllow() {
	cw.mu.Lock()
	routes := cw.routes
	cw.routes = make(map[string]bool)
	hadNRPT := cw.nrptDone
	cw.nrptDone = false
	cw.mu.Unlock()

	for ip := range routes {
		runRouteDelete(ip + "/32")
	}
	if hadNRPT {
		if err := nrptRemoveAllTagged(); err != nil {
			log.Printf("[CAPTIVE] Failed to remove NRPT rules: %v", err)
		}
	}
	if len(routes) > 0 || hadNRPT {
		flushSystemDNSCache()
	}
}

// captiveAllowName — is the name already in the base allow list.
func captiveAllowName(host string) bool {
	for _, n := range captiveAllowNames {
		if n == host {
			return true
		}
	}
	return false
}

// captiveDNSServers — which DNS to consider "the network's": the original DHCP DNS
// captured before the override to the proxy; fallback — the gateway.
func captiveDNSServers(iface, gateway string) []string {
	dnsProxyMu.Lock()
	var orig []string
	if originalDNSByIf != nil {
		orig = originalDNSByIf[iface]
	}
	dnsProxyMu.Unlock()
	return sanitizeDNSServers(orig, gateway)
}

// dnsOverrideActive — does the client override system DNS to its proxy on this interface.
func dnsOverrideActive(iface string) bool {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()
	if originalDNSByIf == nil {
		return false
	}
	_, ok := originalDNSByIf[iface]
	return ok
}

// addAllowRoute adds a /32 route via the gateway and records it for cleanup.
func (cw *captiveWatcher) addAllowRoute(ipStr, gw string) {
	cw.mu.Lock()
	_, exists := cw.routes[ipStr]
	need := !exists && !cw.stoppedLocked()
	if need {
		cw.routes[ipStr] = false // reserved so the probe goroutines don't duplicate it
	}
	cw.mu.Unlock()
	if !need {
		return
	}
	if !runRouteAdd(ipStr+"/32", gw) {
		cw.mu.Lock()
		delete(cw.routes, ipStr)
		cw.mu.Unlock()
		return
	}
	cw.mu.Lock()
	if v, ok := cw.routes[ipStr]; ok && !v {
		cw.routes[ipStr] = true
	}
	cw.mu.Unlock()
}

// resolveAllowed resolves a name via the network's DNS and adds /32 routes for
// the answers. Returns the resolved IPv4s.
func (cw *captiveWatcher) resolveAllowed(name string, dnsServers []string) []net.IP {
	cw.mu.Lock()
	gw := cw.gw
	cw.mu.Unlock()
	if gw == "" {
		return nil
	}
	var ips []net.IP
	for _, srv := range dnsServers {
		res, err := resolveDomainA(name, srv, "")
		if err != nil || len(res) == 0 {
			continue
		}
		ips = res
		break
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			cw.addAllowRoute(v4.String(), gw)
		}
	}
	if len(ips) > 0 {
		log.Printf("[CAPTIVE] %s → %v/32 past the tunnel", name, ips)
	}
	return ips
}

// removeProbeRoutes removes routes added by a probe that ended with a verdict
// of a healthy network (only the routes, not the reserved slots).
func (cw *captiveWatcher) removeProbeRoutes() {
	cw.mu.Lock()
	var ips []string
	for ip, added := range cw.routes {
		if added {
			ips = append(ips, ip)
		}
	}
	for _, ip := range ips {
		delete(cw.routes, ip)
	}
	cw.mu.Unlock()
	for _, ip := range ips {
		runRouteDelete(ip + "/32")
	}
}

// captiveHTTPGet — plain GET without following redirects (the portal is revealed
// by the first response), without system proxies.
func captiveHTTPGet(rawURL string) (statusCode int, body []byte, location string) {
	client := &http.Client{
		Timeout: captiveHTTPTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: captiveHTTPTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, b, resp.Header.Get("Location")
}

// flushSystemDNSCache resets the Windows resolver cache after rule changes.
// Overridden per-OS (stub — for non-Windows builds).
func flushSystemDNSCache() { flushSystemDNSCacheOS() }
