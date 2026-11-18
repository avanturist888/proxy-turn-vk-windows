//go:build windows
// +build windows

package core

// NRPT rules for captive mode: only the entry host gets an exact rule pointing
// to a resolver verified by a direct A query. A host-specific rule takes
// precedence over global and unrelated suffix NRPT policies. The client runs
// elevated (wintun/routes), so NRPT is available to it.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
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

// launchCaptivePortalOS opens the validated login URL in the default browser.
// Explorer receives only our generated .url path as one argument: no URL scheme
// with colons is parsed by Explorer, no shell is involved, and the browser starts
// in the logged-in user's context rather than with this elevated client's token.
func launchCaptivePortalOS(entryURL string) error {
	normalized, ok := normalizeCaptiveEntryURL(entryURL)
	if !ok {
		return fmt.Errorf("captive: отклонён URL страницы входа %q", strings.TrimSpace(entryURL))
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("captive-login-%d.url", time.Now().UnixNano()))
	contents := []byte("[InternetShortcut]\r\nURL=" + normalized + "\r\n")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		return fmt.Errorf("captive: запись ярлыка страницы входа: %w", err)
	}

	cmd := hiddenCmd("explorer.exe", path)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("explorer .url: %w", err)
	}
	// Успех — именно запуск shell-процесса. Его последующий код выхода (в том
	// числе 1 у explorer) ничего не говорит о том, открылся ли браузер.
	_ = cmd.Process.Release()
	go func() {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		<-timer.C
		_ = os.Remove(path)
	}()
	return nil
}

// isIPv4Literal — strict check of an IPv4 string (protection against injection
// into a PowerShell command): net.ParseIP parses only valid IP literals.
func isIPv4Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}
