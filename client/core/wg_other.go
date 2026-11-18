//go:build !windows
// +build !windows

package core

import "net"

func SetupWindowsWireGuard(rawConf, ifaceName string, customDNS []string, excludeDomains []string) error {
	return nil
}

// TeardownWindowsWireGuard — no-op на не-Windows платформах.
func TeardownWindowsWireGuard() {}

// runRouteAdd / runRouteDelete — заглушки для не-Windows. На других платформах
// exclude-маршруты не используются (WG поднимается в режиме клиента через
// встроенный API ОС), поэтому функции возвращают «не добавлено».
func runRouteAdd(cidr, gateway string) bool {
	return false
}

func runRouteDelete(cidr string) {}

// applyTurnHostRoute — no-op на не-Windows платформах.
func applyTurnHostRoute(ip net.IP) {}

// detectPhysicalGateway — заглушка для общего captive-вотчера.
func detectPhysicalGateway(excludeIface string) (gateway, ifaceName string) {
	return "", ""
}

// NRPT-заглушки и сброс DNS-кэша для не-Windows: captive-режим использует их
// только из общего кода, на других платформах правила NRPT не существуют.
func nrptAddRule(namespace string, servers []string) error {
	return nil
}

func nrptRemoveAllTagged() error { return nil }

func nrptRemoveRule(namespace string) error { return nil }

func flushSystemDNSCacheOS() {}

// launchCaptivePortalOS — заглушка на не-Windows: системный браузер открывается только там.
func launchCaptivePortalOS(entryURL string) error { return nil }
