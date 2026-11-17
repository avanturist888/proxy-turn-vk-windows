//go:build windows
// +build windows

package core

// NRPT rules for captive mode: system resolution of allowed names (probes and
// the portal) via the network's DHCP DNS. NRPT is more specific than catch-all
// rules ("." and wide zones), so it wins even with a configured bank split.
// The client runs elevated (wintun/routes), so NRPT is available to it.

import (
	"fmt"
	"net"
	"strings"
)

// nrptAddRule adds one rule: namespace — exact name (subdomains are covered automatically),
// NameServers — network DNS, Comment — the tag by which removal searches for it.
func nrptAddRule(namespace string, servers []string) error {
	if !validCaptiveHost(namespace) {
		return fmt.Errorf("captive: NRPT namespace %q rejected", namespace)
	}
	for _, s := range servers {
		if !isIPv4Literal(s) {
			return fmt.Errorf("captive: NRPT server %q rejected", s)
		}
	}
	ps := fmt.Sprintf(`Add-DnsClientNrptRule -Namespace '%s' -NameServers '%s' -Comment '%s' | Out-Null`,
		namespace, strings.Join(servers, ","), captiveNRPTTag)
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Add-DnsClientNrptRule: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nrptRemoveAllTagged removes all NRPT rules with the captive-mode tag — ours
// and any leftovers from a previous run.
func nrptRemoveAllTagged() error {
	ps := fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | ForEach-Object { Remove-DnsClientNrptRule -Namespace $_.Namespace -Force } | Out-Null`,
		captiveNRPTTag)
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Remove-DnsClientNrptRule: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushSystemDNSCacheOS — drop the resolver cache after rule changes.
func flushSystemDNSCacheOS() {
	_ = hiddenCmd("ipconfig", "/flushdns").Run()
}

// isIPv4Literal — strict check of an IPv4 string (protection against injection
// into a PowerShell command): net.ParseIP parses only valid IP literals.
func isIPv4Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}
