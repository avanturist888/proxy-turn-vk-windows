package core

// Captive portals (guest Wi-Fi with an authorization page).
//
// Until the portal is authorized, the tunnel cannot come up: the portal suppresses
// someone else's traffic and substitutes TLS (VK/TURN are unreachable), and the DNS
// override to the local proxy makes system resolution dependent on the dead tunnel —
// the browser does not resolve even the portal's own page.
//
// The process-scoped watcher breaks the circle without hardcoding specific portals:
//   1. Plain-HTTP probes (NCSI and generate_204) go directly through the physical
//      gateway. A redirect or a substituted body reveals the portal.
//   2. The interface DNS remains the network DNS until the network is usable. Only
//      the entry host gets an exact NRPT rule, and only to a resolver that actually
//      returned A records. This is required even when the resolver is also present
//      in the adapter DNS: pre-existing NRPT rules take precedence over adapter DNS.
//   3. /32 routes past the tunnel are added only for the probe, its DNS servers and
//      the portal. Probe routes from an inconclusive attempt are removed again.
//
// A successful probe, or a tunnel with live workers, restores the DNS override and
// removes the captive rules. The watcher and its portal state survive WG teardown
// and reconnects; a network change, user disconnect or application shutdown clears them.

import (
	"bytes"
	"context"
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

	// Frequency of network observation and of re-checks in captive mode.
	captiveNetworkEvery = 3 * time.Second
	captiveProbeEvery   = 10 * time.Second
	captiveHTTPTimeout  = 5 * time.Second

	captiveUnknownMaxAttempts = 3
	captiveUnknownRetryBase   = 5 * time.Second

	// Live-tunnel proof needs two consecutive ticks; a formerly open network
	// needs three dead ticks before probing and portal handling resume.
	captiveOpenAliveTicks = 2
	captiveOpenDeadTicks  = 3
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

// Base probe names are derived from captiveProbeTargets. The entry host receives
// an exact NRPT rule regardless of this list, including when it is a probe name.

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
	captiveUnknown captiveVerdict = iota // сеть не отвечает — портал не подтверждён
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
// no empty or overly long labels, without a trailing dot. An IP literal cannot have
// a name rule. An IP-only portal therefore needs a /32 route to open; without one,
// its page remains unreachable (a known limitation).
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

// captiveNRPTRule is the part of an NRPT rule relevant to the entry-host decision.
type captiveNRPTRule struct {
	namespace string
	servers   []string
}

// captiveResolutionEnv describes rules that can affect system name resolution.
// Adapter DNS is deliberately absent: any NRPT rule wins over adapter DNS, and
// the exact entry-host rule is mandatory even with no NRPT rules at all.
type captiveResolutionEnv struct {
	nrptRules []captiveNRPTRule
}

// captiveNRPTNeeded reports whether an exact entry-host rule must be installed.
// Global and suffix rules never suppress it. An identical rule already installed
// by this watcher suppresses only a duplicate; a changed resolver replaces it.
func captiveNRPTNeeded(host, resolver string, env captiveResolutionEnv) bool {
	if !validCaptiveHost(host) || net.ParseIP(resolver) == nil || net.ParseIP(resolver).To4() == nil {
		return false
	}
	for _, rule := range env.nrptRules {
		if rule.namespace == host && len(rule.servers) == 1 && rule.servers[0] == resolver {
			return false
		}
	}
	return true
}

// captiveUnknownRetry returns the delay before another inconclusive probe.
// The final unknown pauses probing until a network change or a live tunnel.
func captiveUnknownRetry(attempt int) (time.Duration, bool) {
	if attempt < 1 || attempt >= captiveUnknownMaxAttempts {
		return 0, false
	}
	return time.Duration(attempt) * captiveUnknownRetryBase, true
}

// ─── Process-scoped watcher ──────────────────────────────────────────────────

type captiveWatcher struct {
	mu           sync.Mutex
	wgIface      string
	gw           string
	iface        string
	generation   uint64
	active       bool
	lastProbe    time.Time // only a definitive open/portal verdict updates this
	nextProbe    time.Time
	probePaused  bool
	unknownTry   int
	openKnown    bool
	aliveTicks   int
	deadTicks    int
	aliveTrusted bool // воркеры наблюдались мёртвыми на текущей сети
	portalHost   string
	portalURL    string
	routes       map[string]bool   // added /32 via the gateway (probe, DNS, portal)
	nrptRules    map[string]string // entry host → verified resolver
	tunnelAlive  func() bool
	stopCh       chan struct{}
	doneCh       chan struct{}
}

var (
	captiveMu     sync.Mutex
	activeCaptive *captiveWatcher
)

// startCaptiveWatch starts the single process-scoped watcher. Subsequent Core
// sessions replace only the interface name and liveness callback; portal state
// and rules remain intact across WG teardown/reconnect.
func startCaptiveWatch(wgIface string, tunnelAlive func() bool) {
	captiveMu.Lock()
	cw := activeCaptive
	if cw != nil {
		cw.mu.Lock()
		cw.wgIface = wgIface
		cw.tunnelAlive = tunnelAlive
		cw.mu.Unlock()
		captiveMu.Unlock()
		return
	}
	cw = &captiveWatcher{
		wgIface:     wgIface,
		routes:      make(map[string]bool),
		nrptRules:   make(map[string]string),
		tunnelAlive: tunnelAlive,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
	activeCaptive = cw
	captiveMu.Unlock()

	// Remove leftovers from a previous process once, not on every WG reconnect.
	_ = nrptRemoveAllTagged()
	go cw.loop()
}

// StopCaptiveWatcher detaches and stops the process-scoped watcher. Portal
// routes and NRPT rules are removed immediately; an in-flight DNS/HTTP probe is
// left to finish in the background and rejects its stale result by stoppedLocked.
func StopCaptiveWatcher() {
	captiveMu.Lock()
	cw := activeCaptive
	if cw != nil {
		activeCaptive = nil
	}
	captiveMu.Unlock()
	if cw == nil {
		return
	}
	cw.mu.Lock()
	if !cw.stoppedLocked() {
		close(cw.stopCh)
	}
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

func (cw *captiveWatcher) loop() {
	defer close(cw.doneCh)
	defer cw.clearAllow()
	ticker := time.NewTicker(captiveNetworkEvery)
	defer ticker.Stop()
	for {
		cw.tick()
		select {
		case <-cw.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// captiveTunnelAction is the I/O-free decision made from consecutive liveness
// observations. The tick performs network operations only after this transition.
type captiveTunnelAction int

const (
	captiveTunnelContinue captiveTunnelAction = iota
	captiveTunnelWait
	captiveTunnelMaintainOpen
	captiveTunnelFinishOpen
	captiveTunnelRecapture
)

// observeTunnelLocked updates open-network liveness streaks. Live ticks are
// trusted only after workers were seen dead on the current network: right after
// a network change old DTLS sessions can keep ActiveConnections>0 for a while.
// Two trusted live ticks are required to finish an unknown/captive state. Once
// open, one or two dead ticks preserve the override, while the third resumes
// probing.
func (cw *captiveWatcher) observeTunnelLocked(alive bool) captiveTunnelAction {
	if alive {
		if !cw.aliveTrusted {
			// Возможно, хвост сессий прежней сети. Доказательство появится с
			// первым мёртвым тиком здесь или с вердиктом зонда (проба при Wait
			// выполняется по расписанию).
			return captiveTunnelWait
		}
		cw.deadTicks = 0
		if cw.openKnown {
			cw.aliveTicks = 0
			return captiveTunnelMaintainOpen
		}
		cw.aliveTicks++
		if cw.aliveTicks < captiveOpenAliveTicks {
			return captiveTunnelWait
		}
		cw.aliveTicks = 0
		return captiveTunnelFinishOpen
	}

	cw.aliveTicks = 0
	cw.aliveTrusted = true
	if !cw.openKnown {
		return captiveTunnelContinue
	}
	cw.deadTicks++
	if cw.deadTicks < captiveOpenDeadTicks {
		return captiveTunnelMaintainOpen
	}
	cw.deadTicks = 0
	cw.openKnown = false
	cw.probePaused = false
	cw.nextProbe = time.Time{}
	cw.unknownTry = 0
	return captiveTunnelRecapture
}

// tick observes the network itself, so it also runs before WG configuration and
// while the orchestrator is between WG sessions.
func (cw *captiveWatcher) tick() {
	cw.mu.Lock()
	if cw.stoppedLocked() {
		cw.mu.Unlock()
		return
	}
	wgIface := cw.wgIface
	cw.mu.Unlock()

	gw, iface := detectPhysicalGateway(wgIface)
	cw.changeNetwork(gw, iface, false)
	if gw == "" || iface == "" {
		return
	}

	cw.mu.Lock()
	if cw.stoppedLocked() {
		cw.mu.Unlock()
		return
	}
	generation := cw.generation
	alive := cw.tunnelAlive != nil && cw.tunnelAlive()
	now := time.Now()
	due := !cw.probePaused && (cw.nextProbe.IsZero() || !now.Before(cw.nextProbe))
	action := cw.observeTunnelLocked(alive)
	cw.mu.Unlock()

	switch action {
	case captiveTunnelWait:
		// Без возврата: пока живость не доказана (хвост прежних сессий или
		// первый из двух живых тиков), запланированный зонд всё равно должен
		// проверить сеть — он даёт независимый вердикт.
	case captiveTunnelFinishOpen:
		// Two trusted live-worker observations are independent proof that the
		// network no longer holds the tunnel. This does not depend on an HTTP
		// verdict.
		cw.finishOpen(gw, iface, generation, false, "живой туннель")
		return
	case captiveTunnelMaintainOpen:
		// A successful probe may have preceded DNS-proxy setup. Re-apply its
		// verdict, and tolerate a short tunnel outage before reopening probes.
		cw.applyDNSOverride(gw, iface, generation, "подтверждённая сеть")
		return
	case captiveTunnelRecapture:
		log.Printf("[CAPTIVE] Туннель не ожил после %d тиков — DNS возвращён сети, пробы возобновлены", captiveOpenDeadTicks)
		recaptureInterfaceDNSForCaptive(iface, gw)
		cw.probe(gw, iface)
		return
	}
	if due {
		cw.probe(gw, iface)
	}
}

// captiveNetworkChanged is called by the route guard only after it has switched
// gateway and recaptured DNS. Forcing a new generation invalidates any probe that
// may have started on the old network in the process watcher's own ticker.
func captiveNetworkChanged(gw, iface string) {
	if cw := currentCaptiveWatcher(); cw != nil {
		cw.changeNetwork(gw, iface, true)
	}
}

// changeNetwork updates the network epoch and clears old-network rules. With
// force=true the epoch advances even for the same gateway (route-guard refresh).
func (cw *captiveWatcher) changeNetwork(gw, iface string, force bool) {
	cw.mu.Lock()
	if cw.stoppedLocked() {
		cw.mu.Unlock()
		return
	}
	if !force && gw == cw.gw && iface == cw.iface {
		cw.mu.Unlock()
		return
	}
	oldGw, oldIface := cw.gw, cw.iface
	hadRules := len(cw.routes) > 0 || len(cw.nrptRules) > 0
	cw.generation++
	cw.gw, cw.iface = gw, iface
	cw.active = false
	cw.openKnown = false
	cw.portalHost, cw.portalURL = "", ""
	cw.lastProbe = time.Time{}
	cw.nextProbe = time.Time{}
	cw.probePaused = false
	cw.unknownTry = 0
	cw.aliveTicks = 0
	cw.deadTicks = 0
	cw.aliveTrusted = false
	cw.mu.Unlock()

	if oldGw != "" || hadRules {
		log.Printf("[CAPTIVE] Network changed (%s via %s → %s via %s) — allow rules removed, rechecking", oldGw, oldIface, gw, iface)
	}
	cw.clearAllow()
}

// probe runs one network check. Gateway/interface are explicit; the generation
// captured here must still be current before every state update or DNS override.
func (cw *captiveWatcher) probe(gw, iface string) {
	cw.mu.Lock()
	generation := cw.generation
	if cw.stoppedLocked() || gw == "" || iface == "" || gw != cw.gw || iface != cw.iface {
		cw.mu.Unlock()
		return
	}
	cw.mu.Unlock()

	verdict, portalHost, portalURL := cw.runProbes(gw, iface, generation)

	switch verdict {
	case captiveOpen:
		cw.finishOpen(gw, iface, generation, true, "успешный зонд")
	case captivePortal:
		cw.enterCaptive(gw, iface, generation, portalHost, portalURL)
	default:
		cw.recordUnknown(gw, iface, generation)
	}
}

// recordUnknown schedules at most three attempts and never writes lastProbe.
func (cw *captiveWatcher) recordUnknown(gw, iface string, generation uint64) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.stoppedLocked() || generation != cw.generation || gw != cw.gw || iface != cw.iface {
		return
	}
	cw.unknownTry++
	delay, retry := captiveUnknownRetry(cw.unknownTry)
	if retry {
		cw.nextProbe = time.Now().Add(delay)
	} else {
		cw.probePaused = true
	}
	if cw.unknownTry == 1 {
		log.Printf("[CAPTIVE] Сеть за %s (%s) не отвечает на пробы — портал не подтверждён", gw, iface)
	}
	if !retry {
		log.Printf("[CAPTIVE] Пробы без ответа: %d — пауза до смены сети или появления живого туннеля", cw.unknownTry)
	}
}

// finishOpen handles both a successful probe and independent live-tunnel proof.
func (cw *captiveWatcher) finishOpen(gw, iface string, generation uint64, fromProbe bool, reason string) {
	cw.mu.Lock()
	if cw.stoppedLocked() || generation != cw.generation || gw != cw.gw || iface != cw.iface {
		cw.mu.Unlock()
		return
	}
	wasActive := cw.active
	firstDefinitive := cw.lastProbe.IsZero()
	if fromProbe {
		cw.lastProbe = time.Now()
	}
	cw.active = false
	cw.openKnown = true
	cw.probePaused = true
	cw.nextProbe = time.Time{}
	cw.unknownTry = 0
	cw.aliveTicks = 0
	cw.deadTicks = 0
	cw.portalHost, cw.portalURL = "", ""
	cw.mu.Unlock()

	if fromProbe && firstDefinitive {
		log.Printf("[CAPTIVE] Первая определённая проба сети (%s via %s): портал не обнаружен", iface, gw)
	}
	if wasActive {
		log.Printf("[CAPTIVE] Сеть освобождена (%s) — правила сняты, DNS через прокси", reason)
		cw.clearAllow()
		emitEvent(Event{Type: EventEvent, Name: "captive_cleared", Data: ""})
	}
	// Remove portal /32 routes first: the proxy's first upstream requests must
	// go through the now-live tunnel, not through a stale direct exception.
	cw.applyDNSOverride(gw, iface, generation, reason)
}

// runProbes проходит таргеты зонда до первого определённого ответа.
// Добавляет /32 маршруты к DNS-серверам и хостам зонда через шлюз. На open и
// unknown удаляет только маршруты, добавленные этой попыткой; правила прежнего
// активного портала сохраняются до вердикта open или живого туннеля.
func (cw *captiveWatcher) runProbes(gw, iface string, generation uint64) (captiveVerdict, string, string) {
	baseline := cw.routeSnapshot()
	dnsServers := captiveDNSServers(iface, gw)
	if gw != "" && !captiveListContains(dnsServers, gw) {
		dnsServers = append(dnsServers, gw)
	}
	if len(dnsServers) == 0 {
		return captiveUnknown, "", ""
	}
	for _, srv := range dnsServers {
		cw.addAllowRoute(srv, gw, generation)
	}

	for _, tgt := range captiveProbeTargets {
		ips := cw.resolveAllowed(tgt.host, dnsServers, gw, generation)
		if len(ips) == 0 {
			continue
		}
		// The HTTP request must use the address obtained by the direct DNS query:
		// system resolution may be controlled by unrelated NRPT rules.
		status, body, location := captiveHTTPGet(tgt.url, ips)
		if status == 0 {
			continue
		}
		v, host := classifyCaptiveProbe(status, body, location, tgt.marker)
		if v == captiveOpen {
			cw.removeProbeRoutes(baseline)
			return v, host, ""
		}
		if v == captivePortal {
			return v, host, location
		}
	}
	cw.removeProbeRoutes(baseline)
	return captiveUnknown, "", ""
}

// captiveFallbackResolvers — публичные резолверы для подбора работающего:
// если DNS сети (DHCP/шлюз) не отвечает именем портала, пробуем их по порядку.
var captiveFallbackResolvers = []string{"77.88.8.8", "8.8.8.8"}

func captiveListContains(list []string, addr string) bool {
	for _, s := range list {
		if s == addr {
			return true
		}
	}
	return false
}

// captiveEntryURL — какой адрес открывать пользователю на портальной сети.
func captiveEntryURL(portalURL, portalHost string) string {
	trimmed := strings.TrimSpace(portalURL)
	if u, err := url.Parse(trimmed); err == nil &&
		(u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
		return trimmed
	}
	if portalHost != "" && validCaptiveHost(portalHost) {
		return "https://" + portalHost + "/"
	}
	return "http://www.msftconnecttest.com/redirect"
}

// enterCaptive activates or refreshes portal state. Newly revealed or changed
// entry hosts are processed on every portal verdict, not only on the first one.
func (cw *captiveWatcher) enterCaptive(gw, iface string, generation uint64, portalHost, portalURL string) {
	cw.mu.Lock()
	if cw.stoppedLocked() || generation != cw.generation || gw != cw.gw || iface != cw.iface {
		cw.mu.Unlock()
		return
	}
	wasActive := cw.active
	previousHost := cw.portalHost
	if portalHost != "" {
		cw.portalHost = portalHost
	}
	if portalURL != "" {
		cw.portalURL = strings.TrimSpace(portalURL)
	}
	portalHost = cw.portalHost
	entryURL := cw.portalURL
	cw.active = true
	cw.openKnown = false
	cw.lastProbe = time.Now()
	cw.nextProbe = time.Now().Add(captiveProbeEvery)
	cw.probePaused = false
	cw.unknownTry = 0
	cw.aliveTicks = 0
	cw.deadTicks = 0
	cw.mu.Unlock()

	hostChanged := portalHost != "" && portalHost != previousHost
	changed := false
	if portalHost != "" {
		// Повторная проверка на каждом portal-вердикте восстанавливает правила
		// после временной ошибки; maps в addAllowRoute/NRPT не дают дублей.
		if cw.allowPortalHost(gw, iface, generation, portalHost) {
			changed = true
		}
	}
	if hostChanged && wasActive {
		log.Printf("[CAPTIVE] Хост портала уточнён: %s → %s", previousHost, portalHost)
	}

	if !wasActive {
		if portalHost != "" {
			log.Printf("[CAPTIVE] Обнаружен портал: %s (шлюз %s через %s)", portalHost, gw, iface)
		} else {
			log.Printf("[CAPTIVE] Обнаружен портал (шлюз %s через %s); хост не раскрыт — пропускаю только зонды", gw, iface)
		}
		emitEvent(Event{Type: EventEvent, Name: "captive_detected", Data: portalHost})

		entry := captiveEntryURL(entryURL, portalHost)
		// The fallback is itself the entry host. Ensure it has a verified resolver,
		// an exact NRPT rule and /32 routes even if its earlier probe DNS failed.
		entryHost := extractPortalHost(entry)
		if entryHost != "" && entryHost != portalHost {
			if cw.allowPortalHost(gw, iface, generation, entryHost) {
				changed = true
			}
		}
		if !cw.portalLaunchCurrent(gw, iface, generation) {
			log.Printf("[CAPTIVE] Сеть сменилась во время подготовки портала — страница старой сети не открывается")
		} else {
			log.Printf("[CAPTIVE] Открываю страницу входа в Edge: %s", entry)
			if err := launchEdgeOS(entry); err != nil {
				log.Printf("[CAPTIVE] Не удалось открыть Edge: %v — откройте страницу входа в Edge/Firefox вручную", err)
			}
		}
	}
	if !wasActive || hostChanged || changed {
		flushSystemDNSCache()
	}
}

// portalLaunchCurrent rejects a delayed Edge launch after a network epoch change.
func (cw *captiveWatcher) portalLaunchCurrent(gw, iface string, generation uint64) bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return !cw.stoppedLocked() && generation == cw.generation &&
		gw == cw.gw && iface == cw.iface && cw.active
}

// allowPortalHost finds a resolver that actually returned A records, adds /32
// routes and installs the mandatory exact NRPT rule. Adapter DNS does not
// suppress that rule. Returns whether rules changed.
func (cw *captiveWatcher) allowPortalHost(gw, iface string, generation uint64, portalHost string) bool {
	servers := captiveDNSServers(iface, gw)
	for _, fb := range captiveFallbackResolvers {
		if !captiveListContains(servers, fb) {
			servers = append(servers, fb)
		}
	}
	changed := false
	for _, srv := range servers {
		if cw.addAllowRoute(srv, gw, generation) {
			changed = true
		}
	}

	resolver := ""
	var ips []net.IP
	for _, srv := range servers {
		res, err := resolveDomainA(portalHost, srv, "")
		if err == nil && len(res) > 0 {
			resolver, ips = srv, res
			break
		}
	}
	if resolver == "" {
		log.Printf("[CAPTIVE] %s: ни один резолвер не ответил — страница входа может не открыться", portalHost)
		return changed
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && cw.addAllowRoute(v4.String(), gw, generation) {
			changed = true
		}
	}
	log.Printf("[CAPTIVE] %s → %v через %s (проверенный резолвер, /32 мимо туннеля)", portalHost, ips, resolver)

	cw.mu.Lock()
	if cw.stoppedLocked() || generation != cw.generation {
		cw.mu.Unlock()
		return changed
	}
	rules := make([]captiveNRPTRule, 0, len(cw.nrptRules))
	for host, srv := range cw.nrptRules {
		rules = append(rules, captiveNRPTRule{namespace: host, servers: []string{srv}})
	}
	_, hadRule := cw.nrptRules[portalHost]
	cw.mu.Unlock()

	env := captiveResolutionEnv{nrptRules: rules}
	if !captiveNRPTNeeded(portalHost, resolver, env) {
		return changed
	}
	if hadRule {
		if err := nrptRemoveRule(portalHost); err != nil {
			log.Printf("[CAPTIVE] Прежнее NRPT-правило для %s не удалено: %v", portalHost, err)
			return changed
		}
		cw.mu.Lock()
		delete(cw.nrptRules, portalHost)
		cw.mu.Unlock()
	}
	if err := nrptAddRule(portalHost, []string{resolver}); err != nil {
		log.Printf("[CAPTIVE] NRPT-правило для %s не добавлено: %v", portalHost, err)
		return changed
	}
	cw.mu.Lock()
	valid := !cw.stoppedLocked() && generation == cw.generation
	if valid {
		cw.nrptRules[portalHost] = resolver
	}
	cw.mu.Unlock()
	if !valid {
		_ = nrptRemoveRule(portalHost)
		return changed
	}
	log.Printf("[CAPTIVE] NRPT %s → %s", portalHost, resolver)
	return true
}

// applyDNSOverride возвращает системный DNS на локальный прокси (анти-лик).
// Поколение и stopped проверяются непосредственно перед применением.
func (cw *captiveWatcher) applyDNSOverride(gw, iface string, generation uint64, reason string) {
	cw.mu.Lock()
	valid := !cw.stoppedLocked() && generation == cw.generation && gw == cw.gw && iface == cw.iface
	cw.mu.Unlock()
	if !valid || iface == "" || dnsOverrideActive(iface) {
		return
	}
	dnsProxyMu.Lock()
	proxy := globalDNSProxy != nil
	dnsProxyMu.Unlock()
	if !proxy {
		return
	}
	if !overrideInterfaceDNS(iface) {
		return
	}
	// netsh может завершиться уже после переключения route guard'а на новую
	// эпоху. В этом случае немедленно откатываем запоздалую подмену, а новая
	// сеть будет проверена отдельно.
	cw.mu.Lock()
	valid = !cw.stoppedLocked() && generation == cw.generation && gw == cw.gw && iface == cw.iface
	cw.mu.Unlock()
	if !valid {
		dnsConfigMu.Lock()
		dnsProxyMu.Lock()
		orig, captured := originalDNSByIf[iface]
		active := dnsOverrideActiveByIf[iface]
		dnsProxyMu.Unlock()
		if captured && active {
			if err := restoreInterfaceDNS(iface, orig); err != nil {
				log.Printf("[DNS] Не удалось откатить запоздалую подмену на %s: %v", iface, err)
			}
			dnsProxyMu.Lock()
			dnsOverrideActiveByIf[iface] = false
			dnsProxyMu.Unlock()
		}
		dnsConfigMu.Unlock()
		return
	}
	flushSystemDNSCacheOS()
	log.Printf("[DNS] %s (%s) — системный DNS снова через локальный прокси", reason, iface)
}

// clearAllow removes the /32 routes and all tagged NRPT rules added by captive mode.
func (cw *captiveWatcher) clearAllow() {
	cw.mu.Lock()
	routes := cw.routes
	cw.routes = make(map[string]bool)
	hadNRPT := len(cw.nrptRules) > 0
	cw.nrptRules = make(map[string]string)
	cw.mu.Unlock()

	for ip, added := range routes {
		if added {
			runRouteDelete(ip + "/32")
		}
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

// captiveDNSServers — which DNS to consider "the network's": the original DNS
// captured before the override to the proxy. Before the first capture, read the
// adapter directly: DHCP DNS is not necessarily the gateway. Gateway is only a
// fallback when no usable IPv4 resolver was found.
func captiveDNSServers(iface, gateway string) []string {
	dnsProxyMu.Lock()
	captured, ok := originalDNSByIf[iface]
	orig := append([]string(nil), captured.servers...)
	dnsProxyMu.Unlock()
	if !ok {
		if cfg, err := getInterfaceDNSConfig(iface); err == nil {
			orig = cfg.servers
		} else {
			log.Printf("[CAPTIVE] Не удалось прочитать DNS адаптера %s: %v", iface, err)
		}
	}
	return sanitizeDNSServers(orig, gateway)
}

func dnsOverrideActive(iface string) bool {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()
	return dnsOverrideActiveByIf[iface]
}

// addAllowRoute adds a /32 route via the gateway and records it for cleanup.
// Reservations and completions are rejected if the network epoch has moved on.
func (cw *captiveWatcher) addAllowRoute(ipStr, gw string, generation uint64) bool {
	cw.mu.Lock()
	_, exists := cw.routes[ipStr]
	need := !exists && !cw.stoppedLocked() && generation == cw.generation && gw == cw.gw
	if need {
		cw.routes[ipStr] = false
	}
	cw.mu.Unlock()
	if !need {
		return false
	}
	if !runRouteAdd(ipStr+"/32", gw) {
		cw.mu.Lock()
		if generation == cw.generation {
			delete(cw.routes, ipStr)
		}
		cw.mu.Unlock()
		return false
	}
	cw.mu.Lock()
	valid := !cw.stoppedLocked() && generation == cw.generation && gw == cw.gw
	if valid {
		if added, ok := cw.routes[ipStr]; ok && !added {
			cw.routes[ipStr] = true
		}
	} else if generation == cw.generation {
		delete(cw.routes, ipStr)
	}
	cw.mu.Unlock()
	if !valid {
		runRouteDelete(ipStr + "/32")
		return false
	}
	return true
}

// resolveAllowed resolves a name via explicit DNS servers and adds /32 routes.
func (cw *captiveWatcher) resolveAllowed(name string, dnsServers []string, gw string, generation uint64) []net.IP {
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
			cw.addAllowRoute(v4.String(), gw, generation)
		}
	}
	if len(ips) > 0 {
		log.Printf("[CAPTIVE] %s → %v/32 past the tunnel", name, ips)
	}
	return ips
}

func (cw *captiveWatcher) routeSnapshot() map[string]struct{} {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	out := make(map[string]struct{}, len(cw.routes))
	for ip := range cw.routes {
		out[ip] = struct{}{}
	}
	return out
}

// removeProbeRoutes removes only routes introduced by the current probe attempt.
func (cw *captiveWatcher) removeProbeRoutes(baseline map[string]struct{}) {
	cw.mu.Lock()
	var ips []string
	for ip, added := range cw.routes {
		if _, existed := baseline[ip]; existed {
			continue
		}
		if added {
			ips = append(ips, ip)
		}
		delete(cw.routes, ip)
	}
	cw.mu.Unlock()
	for _, ip := range ips {
		runRouteDelete(ip + "/32")
	}
}

// captiveHTTPGet performs a plain GET without redirects or system proxies. Every
// A record is tried until one answers; the Host and URL remain the original ones.
// Directly dialing the resolved address bypasses system NRPT resolution safely.
func captiveHTTPGet(rawURL string, ips []net.IP) (statusCode int, body []byte, location string) {
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		status, body, location := captiveHTTPGetIP(rawURL, v4.String())
		if status != 0 {
			return status, body, location
		}
	}
	return 0, nil, ""
}

func captiveHTTPGetIP(rawURL, probeIP string) (statusCode int, body []byte, location string) {
	dialer := &net.Dialer{Timeout: captiveHTTPTimeout}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: captiveHTTPTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(probeIP, port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   captiveHTTPTimeout,
		Transport: transport,
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
