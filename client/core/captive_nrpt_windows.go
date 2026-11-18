//go:build windows
// +build windows

package core

// NRPT rules for captive mode: only the entry host gets an exact rule pointing
// to a resolver verified by a direct A query. A host-specific rule takes
// precedence over global and unrelated suffix NRPT policies. The client runs
// elevated (wintun/routes), so NRPT is available to it.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

// nrptAddRule adds one host rule with the captive tag used for later removal.
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

// Remove-DnsClientNrptRule on this Windows build takes -Name with the rule's
// GUID Name property (Get-DnsClientNrptRule returns it per rule), not
// -Namespace — that parameter does not exist here (verified 18.11; the docs
// describe the older build). Removal errors must surface: without
// ErrorAction Stop a failed removal leaves stale rules that break NCSI and
// system resolution on every network afterwards.
const nrptRemoveScriptTail = `; if ($failed -gt 0) { exit 1 }`

// nrptRemoveRule removes the tagged rule for one entry host before replacement.
func nrptRemoveRule(namespace string) error {
	if !validCaptiveHost(namespace) {
		return fmt.Errorf("captive: NRPT namespace %q rejected", namespace)
	}
	ps := fmt.Sprintf(`$failed = 0
Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' -and @($_.Namespace) -contains '%s' } | ForEach-Object {
  try { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop } catch { $failed++; Write-Output $_.Exception.Message }
} `+nrptRemoveScriptTail, captiveNRPTTag, namespace)
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Remove-DnsClientNrptRule: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nrptRemoveAllTagged removes all NRPT rules with the captive-mode tag — ours
// and any leftovers from a previous run.
func nrptRemoveAllTagged() error {
	ps := fmt.Sprintf(`$failed = 0
Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | ForEach-Object {
  try { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop } catch { $failed++; Write-Output $_.Exception.Message }
} `+nrptRemoveScriptTail, captiveNRPTTag)
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Remove-DnsClientNrptRule: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushSystemDNSCacheOS — сброс кэша резолвера после смены правил.
func flushSystemDNSCacheOS() {
	_ = hiddenCmd("ipconfig", "/flushdns").Run()
}

// launchEdgeOS opens Edge through the shell's microsoft-edge: protocol handler.
// The already-running explorer.exe launches it in the logged-in user's context,
// rather than inheriting this elevated client's token. The untrusted redirect
// URL is one CreateProcess argument; no cmd shell or elevated Edge fallback is used.
func launchEdgeOS(entryURL string) error {
	entryURL = strings.TrimSpace(entryURL)
	u, err := url.Parse(entryURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("captive: отклонён URL страницы входа %q", entryURL)
	}
	cmd := hiddenCmd("explorer.exe", "microsoft-edge:"+entryURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// explorer often exits with 1 after successfully handing the URL to
			// the shell. Once it started, its exit code does not prove Edge failed.
			log.Printf("[CAPTIVE] explorer принял URL и завершился с кодом %d (штатная передача в shell)", exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("explorer microsoft-edge: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isIPv4Literal — strict check of an IPv4 string (protection against injection
// into a PowerShell command): net.ParseIP parses only valid IP literals.
func isIPv4Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}
