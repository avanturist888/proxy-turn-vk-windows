//go:build windows
// +build windows

package core

import (
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	// wintunAPI provides direct access to wintun.dll for adapter lifecycle management.
	wintunMod        = syscall.NewLazyDLL("wintun.dll")
	procWintunOpen   = wintunMod.NewProc("WintunOpenAdapter")
	procWintunClose  = wintunMod.NewProc("WintunCloseAdapter")
	procWintunDelete = wintunMod.NewProc("WintunDeleteAdapter")
)

// setFixedTUNGUID устанавливает фиксированный GUID для wintun-адаптера на основе
// имени интерфейса. Без этого wireguard-go/tun.CreateTUN передаёт nil GUID,
// и Windows генерирует новый GUID при каждом подключении, создавая новый адаптер
// ("WDTT", "WDTT 2", "WDTT 3"…). С фиксированным GUID один и тот же адаптер
// переиспользуется.
func setFixedTUNGUID(name string) {
	h := fnv.New128a()
	h.Write([]byte(name))
	sum := h.Sum(nil)
	tun.WintunStaticRequestedGUID = &windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
		Data4: [8]byte{sum[8], sum[9], sum[10], sum[11], sum[12], sum[13], sum[14], sum[15]},
	}
	log.Printf("[WG] Установлен фиксированный GUID для TUN-адаптера %s", name)
}

// cleanupWintunAdapters удаляет ВСЕ существующие wintun-адаптеры с заданным именем
// (и их числовыми суффиксами) через wintun API, а затем PowerShell как fallback.
// Без этого каждый вызов tun.CreateTUN() создаёт новый адаптер ("WDTT", "WDTT 2"…),
// т.к. wintun использует случайный GUID при каждом создании, а Close() не удаляет
// адаптер из Windows.
func cleanupWintunAdapters(name string) {
	log.Printf("[WG] Очистка старых TUN-адаптеров %s...", name)

	// Method 1: wintun API — WintunOpenAdapter + WintunDeleteAdapter в цикле
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		log.Printf("[WG] cleanupWintunAdapters: UTF16PtrFromString error: %v", err)
	} else {
		deleted := 0
		for i := 0; i < 200; i++ {
			handle, _, _ := procWintunOpen.Call(uintptr(unsafe.Pointer(namePtr)))
			if handle == 0 {
				break
			}
			procWintunDelete.Call(handle)
			procWintunClose.Call(handle)
			deleted++
		}
		if deleted > 0 {
			log.Printf("[WG] Удалено %d TUN-адаптер(ов) %s через wintun API", deleted, name)
		}
	}
}

// wintunEmbedded — встроенный wintun.dll (signed by WireGuard LLC, 0.14.1 amd64).
// Извлекается в `%LOCALAPPDATA%\wdtt\wintun.dll` при первом старте, чтобы
// пользователю не нужно было таскать DLL рядом с exe.
// Источник: client/core/assets/wintun.dll (427552 байт, SHA256 в комментарии
// рядом — обновлять при замене файла).
//
//go:embed assets/wintun.dll
var wintunEmbedded []byte

// hideWindow скрывает консольное окно при запуске дочерних процессов.
// CREATE_NO_WINDOW (0x08000000) не создаёт консоль для процесса, HideWindow
// скрывает окно если родитель Wails уже скрыл свою. Двойная защита от
// мелькающих чёрных окон cmd/powershell при старте туннеля.
const createNoWindow = 0x08000000

func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}

type wgConfig struct {
	privateKey              string
	address                 string
	dns                     string
	mtu                     int
	peerPublicKey           string
	peerEndpoint            string
	peerAllowedIPs          []string
	peerPersistentKeepalive int
}

// base64ToHex конвертирует base64-кодированный ключ WireGuard в hex-строку для IPC
func base64ToHex(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("декодирование base64: %w", err)
	}
	return hex.EncodeToString(decoded), nil
}

// teardownWindowsWireGuard убирает всё, что наставил SetupWindowsWireGuard:
// исключающие маршруты, default route, IP-адрес, локальный DNS-прокси
// и TUN-устройство. Безопасна к повторному вызову и конкурентному вызову.
// Используем mutex + nil-guarded function вместо sync.Once, потому что
// sync.Once нельзя безопасно реинициализировать (Do после повторного
// присвоения переменной — data race по спецификации Go).
var (
	wgTeardownMu sync.Mutex
	wgTeardownFn func()
)

// globalDNSProxy и originalDNSByIf управляют локальным DNS-прокси на
// 127.0.0.1:53 и оригинальным DNS пользователя, который мы временно
// подменяем на 127.0.0.1, чтобы все приложения ходили через наш прокси
// (а не через локальный DNS провайдера, который может перехватывать/резать).
type interfaceDNSConfig struct {
	servers []string
	source  string // "dhcp" or "static"
}

var (
	dnsConfigMu           sync.Mutex // serializes netsh DNS changes and their activity flags
	dnsProxyMu            sync.Mutex
	globalDNSProxy        *dnsProxy
	originalDNSByIf       = make(map[string]interfaceDNSConfig)
	dnsOverrideActiveByIf = make(map[string]bool) // iface → DNS сейчас подменён на 127.0.0.1
	activeDomainExcluder  *domainExcluder         // гибридный excluder для доменных исключений
)

func SetupWindowsWireGuard(rawConf, ifaceName string, customDNS []string, excludeDomains []string) error {
	cfg, err := parseWireGuardConfig(rawConf)
	if err != nil {
		return err
	}

	if cfg.mtu <= 0 {
		cfg.mtu = 1280
	}

	if err := ensureWintunDLL(); err != nil {
		return err
	}

	// Delete any existing wintun adapters before creating a new one.
	cleanupWintunAdapters(ifaceName)
	// Set a fixed GUID so CreateTUN reuses the same adapter instead of creating
	// a new one with a random GUID each time.
	setFixedTUNGUID(ifaceName)
	tunDev, err := tun.CreateTUN(ifaceName, cfg.mtu)
	if err != nil {
		return fmt.Errorf("CreateTUN: %w", err)
	}

	actualName, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("TUN name: %w", err)
	}
	log.Printf("[WG] TUN интерфейс создан: %s (MTU=%d)", actualName, cfg.mtu)

	if err := setWindowsInterfaceAddress(actualName, cfg.address); err != nil {
		_ = tunDev.Close()
		return err
	}

	if cfg.dns != "" {
		if err := setWindowsInterfaceDNS(actualName, cfg.dns); err != nil {
			log.Printf("[WG] Предупреждение: не удалось задать DNS: %v", err)
		}
	}

	// Запоминаем оригинальный шлюз ДО того, как WG перехватит маршрутизацию.
	// Сначала быстрый путь через GetAdaptersAddresses (без PowerShell), он же
	// используется route guard'ом; PowerShell/route print — fallback.
	origGateway, origIface := detectPhysicalGateway(actualName)
	if origGateway == "" || origIface == "" {
		origGateway, origIface = getDefaultGateway()
	}
	if origGateway == "" && origIface != "" {
		origGateway = getInterfaceGateway(origIface)
	}
	if origGateway != "" && origIface != "" {
		log.Printf("[WG] Оригинальный шлюз: %s (интерфейс: %s)", origGateway, origIface)
	} else {
		log.Printf("[WG] Не удалось определить оригинальный шлюз (gw=%q iface=%q)", origGateway, origIface)
	}

	if err := setWindowsInterfaceMetric(actualName, 1); err != nil {
		log.Printf("[WG] Предупреждение: не удалось задать метрику интерфейса: %v", err)
	}

	if err := addWindowsDefaultRoute(actualName); err != nil {
		log.Printf("[WG] Предупреждение: не удалось добавить маршрут по умолчанию: %v", err)
	}

	// TURN-исключения: добавляем /32 маршруты на TURN-сервера через оригинальный шлюз.
	// Это критично — без них WG-default route 0.0.0.0/0 перехватит трафик к TURN,
	// и туннель упадёт в первую же секунду. Состояние живёт в wgRuntime, чтобы
	// route guard мог переставить маршруты при смене сети, а AddTurnExcludeIP —
	// добавить новые TURN IP на лету.
	rt := &wgRuntime{
		ifaceName:   actualName,
		gateway:     origGateway,
		iface:       origIface,
		turnRoutes:  make(map[string]bool),
		turnIface:   origIface,
		dnsOverride: len(customDNS) > 0,
	}
	if origGateway != "" && origIface != "" {
		rt.applyTurnRoutes()
	} else {
		log.Printf("[WG] ⚠ TURN-исключения НЕ добавлены — туннель может быть нестабильным (route guard добавит их, когда появится шлюз)")
	}

	// VK CIDR + DNS-исключения: используем route add (более простой, чем netsh).
	// Без этого id.vk.ru, login.vk.com и публичные DNS окажутся внутри туннеля,
	// что ломает авторизацию в VK и замедляет резолв.
	applyExcludeRoutes(origGateway, origIface)

	bind := conn.NewDefaultBind()
	logger := device.NewLogger(device.LogLevelSilent, "WG")
	wgDev := device.NewDevice(tunDev, bind, logger)

	// Конвертируем приватный ключ из base64 в hex для IPC
	hexPrivateKey, err := base64ToHex(cfg.privateKey)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("конвертирование приватного ключа: %w", err)
	}

	// Конвертируем публичный ключ пира из base64 в hex для IPC
	hexPeerPublicKey, err := base64ToHex(cfg.peerPublicKey)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("конвертирование публичного ключа пира: %w", err)
	}

	uapiConf := strings.Join([]string{
		fmt.Sprintf("private_key=%s", hexPrivateKey),
		"listen_port=0",
		"replace_peers=true",
		fmt.Sprintf("public_key=%s", hexPeerPublicKey),
		fmt.Sprintf("endpoint=%s", cfg.peerEndpoint),
		fmt.Sprintf("allowed_ip=%s", strings.Join(cfg.peerAllowedIPs, ",")),
		fmt.Sprintf("persistent_keepalive_interval=%d", cfg.peerPersistentKeepalive),
	}, "\n")

	if err := wgDev.IpcSet(uapiConf); err != nil {
		wgDev.Close()
		return fmt.Errorf("IpcSet: %w", err)
	}

	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		return fmt.Errorf("Up: %w", err)
	}

	// Регистрируем teardown. Делаем это ПОСЛЕ успешного Up(), чтобы при ошибке
	// выше маршруты не остались без устройства.
	wgTeardownMu.Lock()
	wgTeardownFn = func() {
		wgTeardownMu.Lock()
		if wgTeardownFn == nil {
			wgTeardownMu.Unlock()
			return // уже отработали
		}
		wgTeardownFn = nil
		wgTeardownMu.Unlock()

		log.Printf("[WG] Teardown интерфейса %s...", actualName)
		// Останавливаем route guard, чтобы он не переставлял маршруты
		// параллельно с их удалением.
		stopRouteGuard()
		// Состояние captive-вотчера и его allow-правила переживают WG-teardown.
		// Сначала останавливаем DNS-прокси и возвращаем оригинальный DNS,
		// чтобы приложения не потеряли резолв после удаления туннеля.
		dnsProxyMu.Lock()
		if globalDNSProxy != nil {
			globalDNSProxy.Stop()
			globalDNSProxy = nil
		}
		dnsProxyMu.Unlock()
		// Восстановление DNS и снятие флага — под dnsConfigMu, чтобы
		// запоздавший applyDNSOverride вотчера не втиснул 127.0.0.1 после
		// восстановления (порядок блокировок: dnsConfigMu → dnsProxyMu).
		dnsConfigMu.Lock()
		dnsProxyMu.Lock()
		for iface, orig := range originalDNSByIf {
			if err := restoreInterfaceDNS(iface, orig); err != nil {
				log.Printf("[DNS] Не удалось восстановить DNS на %s: %v", iface, err)
			}
			delete(originalDNSByIf, iface)
			delete(dnsOverrideActiveByIf, iface)
		}
		dnsProxyMu.Unlock()
		dnsConfigMu.Unlock()
		_ = hiddenCmd("ipconfig", "/flushdns").Run()

		// Останавливаем domain excluder (удаляет все /32 маршруты).
		if activeDomainExcluder != nil {
			activeDomainExcluder.Stop()
			dnsProxyMu.Lock()
			activeDomainExcluder = nil
			dnsProxyMu.Unlock()
		}

		wgDev.Close()
		cleanupWintunAdapters(actualName)
		// Сначала убираем exclude-маршруты, чтобы вернуть трафик в норму,
		// даже если удаление TUN/default route по какой-то причине отвалится.
		removeExcludeRoutes()
		rt.mu.Lock()
		turnIface := rt.turnIface
		rt.mu.Unlock()
		rt.removeTurnRoutes(turnIface)
		_ = runNetsh("interface", "ipv4", "delete", "route", "0.0.0.0/0", actualName, "0.0.0.0", "store=active")
		_ = runNetsh("interface", "ipv4", "delete", "address", fmt.Sprintf("name=%s", actualName), fmt.Sprintf("address=%s", cfg.address), "store=active")
		log.Printf("[WG] Teardown завершён")
	}
	wgTeardownMu.Unlock()

	// Если задан customDNS — поднимаем локальный DNS-прокси на 127.0.0.1:53
	// и подменяем системный DNS на 127.0.0.1. Так приложения резолвят через
	// наш прокси (провайдер не может перехватить localhost), а прокси ходит
	// на upstream-ы через туннель (AllowedIPs 0.0.0.0/0), обходя любые
	// IP-блокировки провайдера.
	if len(customDNS) > 0 {
		// Source IP для DNS-прокси = IP WireGuard-туннеля (cfg.address).
		// Все DNS-запросы идут через туннель → VPS делает SNAT → 8.8.8.8
		// отвечает VPS → ответ возвращается через туннель.
		// Если использовать Ethernet IP (192.168.x.x), VPS не сможет
		// замаскировать пакет (SNAT только для 10.66.0.0/24), и DNS
		// к заблокированным в РФ upstream-ам (8.8.8.8, 1.1.1.1) упадёт
		// по таймауту.
		srcIP := ""
		if host, _, err := net.ParseCIDR(cfg.address); err == nil {
			srcIP = host.String()
		}
		log.Printf("[DNS] Source IP для upstream=%s (origIface=%q)", srcIP, origIface)
		proxy := newDNSProxy(customDNS, srcIP)
		proxy.SetCaptiveUpstreamHandler(func() (bool, []string, string) {
			cw := currentCaptiveWatcher()
			if cw == nil {
				return false, nil, ""
			}
			return cw.captiveDNSUpstream()
		})
		if err := proxy.Start(); err != nil {
			log.Printf("[DNS] Не удалось запустить локальный прокси: %v (возможно, порт 53 занят)", err)
		} else {
			dnsProxyMu.Lock()
			globalDNSProxy = proxy
			dnsProxyMu.Unlock()

			// Инициализируем domain excluder (IP-уровень исключений).
			// Резолвит исключённые домены через те же DNS-серверы, что и прокси
			// (8.8.8.8, 1.1.1.1 через туннель), и добавляет /32 маршруты через
			// оригинальный шлюз. Это работает независимо от того, какой DNS
			// использует приложение — сетевой уровень всегда выберет /32.
			if len(excludeDomains) > 0 && origGateway != "" && len(customDNS) > 0 {
				excluder := newDomainExcluder(excludeDomains, origGateway, origIface, customDNS, srcIP)
				excluder.Start()
				// Хук в DNS-прокси: для wildcard-паттернов excluder резолвит
				// поддомены on-demand при DNS-запросе и возвращает IP для ответа.
				proxy.SetExcludedDomainHandler(func(hostname string) []net.IP {
					return excluder.HandleExcludedDNS(hostname)
				})
				dnsProxyMu.Lock()
				activeDomainExcluder = excluder
				dnsProxyMu.Unlock()
			} else if len(excludeDomains) > 0 {
				log.Printf("[DOMEXCL] Доменные исключения не активированы (gateway=%q, dns=%v)", origGateway, customDNS)
			}

			// Первичная сеть: снимаем её DNS (DHCP, при пустом — шлюз) как
			// «оригинал» для открата. Подмена на 127.0.0.1 произойдёт после
			// успешной пробы (applyDNSOverride) — на портальной сети резолв
			// остаётся сетевым, чтобы страница входа открывалась.
			recaptureInterfaceDNS(origIface, origGateway)
			// Сбрасываем кэш, чтобы новые запросы пошли через актуальный резолв.
			_ = hiddenCmd("ipconfig", "/flushdns").Run()
		}
	}

	go func() {
		<-wgDev.Wait()
		log.Printf("[WG] WireGuard устройство %s остановлено", actualName)
	}()

	// Мониторим смену физического шлюза/интерфейса и переставляем исключения.
	startRouteGuard(rt)

	return nil
}

// TeardownWindowsWireGuard убирает WireGuard-интерфейс и все маршруты.
// Безопасно вызывать многократно и из любого места (включая defer).
func TeardownWindowsWireGuard() {
	wgTeardownMu.Lock()
	fn := wgTeardownFn
	wgTeardownMu.Unlock()
	if fn != nil {
		fn()
	}
}

func parseWireGuardConfig(raw string) (*wgConfig, error) {
	var cfg wgConfig
	cfg.mtu = 1280
	cfg.peerAllowedIPs = []string{"0.0.0.0/0"}
	cfg.peerPersistentKeepalive = 25

	section := ""
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case "[Interface]":
			section = "interface"
			continue
		case "[Peer]":
			section = "peer"
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		if section == "interface" {
			switch key {
			case "privatekey":
				cfg.privateKey = value
			case "address":
				cfg.address = value
			case "dns":
				cfg.dns = value
			case "mtu":
				if mtu, err := strconv.Atoi(value); err == nil {
					cfg.mtu = mtu
				}
			}
		} else if section == "peer" {
			switch key {
			case "publickey":
				cfg.peerPublicKey = value
			case "endpoint":
				cfg.peerEndpoint = value
			case "allowedips":
				cfg.peerAllowedIPs = strings.Split(value, ",")
			case "persistentkeepalive":
				if keepalive, err := strconv.Atoi(value); err == nil {
					cfg.peerPersistentKeepalive = keepalive
				}
			}
		}
	}

	if cfg.privateKey == "" {
		return nil, fmt.Errorf("missing private key in WireGuard config")
	}
	if cfg.address == "" {
		return nil, fmt.Errorf("missing interface address in WireGuard config")
	}
	if cfg.peerPublicKey == "" {
		return nil, fmt.Errorf("missing peer public key in WireGuard config")
	}
	if cfg.peerEndpoint == "" {
		return nil, fmt.Errorf("missing peer endpoint in WireGuard config")
	}

	return &cfg, nil
}

func setWindowsInterfaceAddress(iface, cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	mask := net.IP(ipnet.Mask).String()
	return runNetsh("interface", "ipv4", "add", "address", fmt.Sprintf("name=%s", iface), fmt.Sprintf("address=%s", ip.String()), fmt.Sprintf("mask=%s", mask), "store=active")
}

func setWindowsInterfaceDNS(iface, dns string) error {
	return runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", iface), "source=static", fmt.Sprintf("address=%s", dns), "register=primary", "validate=no")
}

// getInterfaceDNSConfig reads every IPv4 DNS server without line-based netsh
// parsing (the first DHCP address shares a line with a localized label). The
// per-interface registry value distinguishes explicit static DNS from DHCP;
// DhcpNameServer may remain populated even when static DNS takes precedence.
func getInterfaceDNSConfig(iface string) (interfaceDNSConfig, error) {
	const ps = `
$alias = $env:WDTT_DNS_IFACE
$servers = @(Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop |
  ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
$guid = (Get-NetAdapter -InterfaceAlias $alias -ErrorAction Stop).InterfaceGuid
$reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
$source = 'dhcp'
if ($null -ne $reg -and -not [string]::IsNullOrWhiteSpace([string]$reg.NameServer)) { $source = 'static' }
[pscustomobject]@{ source = $source; servers = @($servers) } | ConvertTo-Json -Compress`
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Env = append(os.Environ(), "WDTT_DNS_IFACE="+iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return interfaceDNSConfig{}, fmt.Errorf("Get-DnsClientServerAddress %s: %w; output=%s", iface, err, strings.TrimSpace(string(out)))
	}
	return parseInterfaceDNSConfig(out)
}

func parseInterfaceDNSConfig(out []byte) (interfaceDNSConfig, error) {
	var raw struct {
		Source  string   `json:"source"`
		Servers []string `json:"servers"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return interfaceDNSConfig{}, fmt.Errorf("parse DNS configuration: %w", err)
	}
	if raw.Source != "dhcp" && raw.Source != "static" {
		return interfaceDNSConfig{}, fmt.Errorf("unknown DNS source %q", raw.Source)
	}
	servers := make([]string, 0, len(raw.Servers))
	for _, server := range raw.Servers {
		server = strings.TrimSpace(server)
		ip := net.ParseIP(server)
		if ip == nil || ip.To4() == nil {
			return interfaceDNSConfig{}, fmt.Errorf("invalid IPv4 DNS server %q", server)
		}
		servers = append(servers, ip.To4().String())
	}
	return interfaceDNSConfig{servers: servers, source: raw.Source}, nil
}

// getInterfaceDNS is kept for callers that need only the effective server list.
func getInterfaceDNS(iface string) []string {
	cfg, err := getInterfaceDNSConfig(iface)
	if err != nil {
		log.Printf("[DNS] Не удалось прочитать DNS %s: %v", iface, err)
		return nil
	}
	return cfg.servers
}

// setInterfaceDNS ставит список DNS-серверов на интерфейс. Первый сервер
// ставится через "set dnsservers source=static address=...", остальные
// добавляются через "add dnsservers".
func setInterfaceDNS(iface string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Ставим первый — "set" всегда перезаписывает текущий список DNS.
	if err := runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", iface), "source=static", fmt.Sprintf("address=%s", servers[0]), "register=primary", "validate=no"); err != nil {
		return err
	}
	// Добавляем остальные (index=2, 3, ...).
	for i := 1; i < len(servers); i++ {
		if err := runNetsh("interface", "ipv4", "add", "dnsservers", fmt.Sprintf("name=%s", iface), fmt.Sprintf("address=%s", servers[i]), fmt.Sprintf("index=%d", i+1), "validate=no"); err != nil {
			return err
		}
	}
	return nil
}

// restoreInterfaceDNS restores both the server list and its original source.
// In particular, an originally DHCP configuration always goes back to DHCP,
// even when a temporary gateway fallback was used during captive mode.
func restoreInterfaceDNS(iface string, orig interfaceDNSConfig) error {
	if orig.source == "dhcp" {
		return runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", iface), "source=dhcp", "validate=no")
	}
	if orig.source != "static" {
		return fmt.Errorf("unknown original DNS source %q", orig.source)
	}
	if len(orig.servers) == 0 {
		return fmt.Errorf("original static DNS list is empty")
	}
	return setInterfaceDNS(iface, orig.servers)
}

// loopbackOnlyDNS identifies our own static 127.0.0.1 override. It must never
// be saved as the rollback configuration, including after a failed DHCP reset.
func loopbackOnlyDNS(cfg interfaceDNSConfig) bool {
	if len(cfg.servers) != 1 {
		return false
	}
	ip := net.ParseIP(cfg.servers[0])
	return ip != nil && ip.IsLoopback()
}

// recaptureInterfaceDNS refreshes the original network DNS without replacing a
// non-empty DHCP answer with the gateway. Static user DNS is restored as static;
// DHCP is re-read as DHCP. Only a genuinely empty DHCP answer gets a temporary
// gateway resolver, while the saved rollback configuration remains source=dhcp.
// Route-guard recapture yields to an already active captive DNS override.
func recaptureInterfaceDNS(iface, gateway string) {
	recaptureInterfaceDNSMode(iface, gateway, false)
}

// recaptureInterfaceDNSForCaptive deliberately withdraws the override after the
// formerly open tunnel stayed dead for several ticks and probing resumed.
func recaptureInterfaceDNSForCaptive(iface, gateway string) {
	recaptureInterfaceDNSMode(iface, gateway, true)
}

func recaptureInterfaceDNSMode(iface, gateway string, force bool) {
	if iface == "" {
		return
	}
	dnsConfigMu.Lock()
	defer dnsConfigMu.Unlock()
	if !force && dnsOverrideActive(iface) {
		log.Printf("[DNS] Recapture %s пропущен: captive override активен", iface)
		return
	}

	dnsProxyMu.Lock()
	previous, hadPrevious := originalDNSByIf[iface]
	dnsOverrideActiveByIf[iface] = false
	dnsProxyMu.Unlock()

	cfg := previous
	if hadPrevious && previous.source == "static" {
		if err := restoreInterfaceDNS(iface, previous); err != nil {
			log.Printf("[DNS] Не удалось вернуть статический DNS на %s: %v", iface, err)
		}
	} else if hadPrevious && previous.source == "dhcp" {
		dhcpErr := runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", iface), "source=dhcp", "validate=no")
		time.Sleep(time.Second) // стек применяет lease не мгновенно
		if current, err := getInterfaceDNSConfig(iface); err == nil {
			if loopbackOnlyDNS(current) {
				log.Printf("[DNS] DHCP reset %s не дал сетевой DNS; loopback override не сохраняем как оригинал", iface)
			} else {
				cfg = current
				if dhcpErr == nil {
					cfg.source = "dhcp"
				}
			}
		} else {
			log.Printf("[DNS] Не удалось перечитать DHCP DNS %s: %v", iface, err)
		}
		if dhcpErr != nil {
			log.Printf("[DNS] Не удалось вернуть DHCP DNS на %s: %v", iface, dhcpErr)
		}
	} else {
		current, err := getInterfaceDNSConfig(iface)
		if err != nil {
			log.Printf("[DNS] Не удалось снять конфигурацию DNS %s: %v", iface, err)
			return
		}
		if loopbackOnlyDNS(current) {
			// A previous process may have exited after the override but before
			// saving its capture. Restore DHCP and never roll back to that loopback.
			log.Printf("[DNS] На %s найден устаревший loopback override — перечитываю DHCP", iface)
			if err := runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", iface), "source=dhcp", "validate=no"); err != nil {
				log.Printf("[DNS] Не удалось сбросить устаревший override на %s: %v", iface, err)
				return
			}
			time.Sleep(time.Second)
			current, err = getInterfaceDNSConfig(iface)
			if err != nil {
				log.Printf("[DNS] Не удалось перечитать DHCP DNS %s: %v", iface, err)
				return
			}
			if loopbackOnlyDNS(current) {
				log.Printf("[DNS] %s всё ещё сообщает только loopback DNS — capture отклонён", iface)
				return
			}
			current.source = "dhcp"
		}
		cfg = current
	}

	if loopbackOnlyDNS(cfg) {
		log.Printf("[DNS] Отклонён loopback-only capture на %s", iface)
		return
	}
	if cfg.source == "dhcp" && len(cfg.servers) == 0 && gateway != "" {
		if err := setInterfaceDNS(iface, []string{gateway}); err == nil {
			log.Printf("[DNS] Сеть не выдала DNS по DHCP — шлюз %s временно работает resolver'ом", gateway)
		} else {
			log.Printf("[DNS] Не удалось задать временный resolver %s на %s: %v", gateway, iface, err)
		}
	}
	dnsProxyMu.Lock()
	originalDNSByIf[iface] = cfg
	dnsOverrideActiveByIf[iface] = false
	dnsProxyMu.Unlock()
	log.Printf("[DNS] DNS сети %s: %v (source=%s, оригинал для отката)", iface, cfg.servers, cfg.source)
}

func setWindowsInterfaceMetric(iface string, metric int) error {
	return runNetsh("interface", "ipv4", "set", "interface", fmt.Sprintf("name=%s", iface), fmt.Sprintf("metric=%d", metric), "store=active")
}

func addWindowsDefaultRoute(iface string) error {
	_ = runNetsh("interface", "ipv4", "delete", "route", "0.0.0.0/0", iface, "0.0.0.0", "store=active")
	return runNetsh("interface", "ipv4", "add", "route", "0.0.0.0/0", iface, "0.0.0.0", "metric=1", "store=active")
}

// getDefaultGateway возвращает текущий IPv4 шлюз по умолчанию и имя интерфейса.
// Сначала пробует PowerShell, затем route print как fallback.
func getDefaultGateway() (gateway string, ifaceName string) {
	// Попытка 1: PowerShell Get-NetRoute
	if g, i := getDefaultGatewayPS(); g != "" && i != "" {
		return g, i
	}
	// Попытка 2: route.exe print (fallback)
	if g, i := getDefaultGatewayRoutePrint(); g != "" && i != "" {
		return g, i
	}
	return "", ""
}

func getDefaultGatewayPS() (gateway string, ifaceName string) {
	cmd := hiddenCmd("powershell", "-NoProfile", "-Command",
		"$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Select-Object -First 1; if($r){[string]$r.NextHop+'|'+$r.InterfaceAlias}")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("[WG] PowerShell get gateway: %v", err)
		return "", ""
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		log.Printf("[WG] PowerShell gateway output: %q → пропускаем", strings.TrimSpace(string(out)))
		return "", ""
	}
	return parts[0], parts[1]
}

func getDefaultGatewayRoutePrint() (gateway string, ifaceName string) {
	out, err := hiddenCmd("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			if gw != "0.0.0.0" && net.ParseIP(gw) != nil {
				// Нужно имя интерфейса — ищем его по IP
				interfaceIP := fields[3]
				if name := findInterfaceNameByIP(interfaceIP); name != "" {
					return gw, name
				}
				return gw, ""
			}
		}
	}
	return "", ""
}

// findInterfaceNameByIP ищет имя Windows-интерфейса по его IP-адресу.
func findInterfaceNameByIP(ipStr string) string {
	out, err := hiddenCmd("powershell", "-NoProfile", "-Command",
		"$ip='"+ipStr+"'; $adapter=Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.IPAddress -eq $ip}|Select-Object -First 1; if($adapter){$adapter.InterfaceAlias}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getInterfaceIPv4 возвращает IPv4-адрес указанного интерфейса (Ethernet и т.п.).
// Используется, чтобы bind DNS-прокси на source IP оригинальной сетевой карты,
// а не на WDTT — иначе ядро отказывается выпускать пакет: source из одной подсети,
// а маршрут ведёт в другую ("unreachable host").
func getInterfaceIPv4(ifaceName string) string {
	if ifaceName == "" {
		return ""
	}
	out, err := hiddenCmd("powershell", "-NoProfile", "-Command",
		"$adapter=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '"+ifaceName+"'|Where-Object{$_.PrefixOrigin -ne 'WellKnown'}|Select-Object -First 1; if($adapter){$adapter.IPAddress}").Output()
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(out))
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

// getInterfaceDefaultGateway получает шлюз по умолчанию для указанного интерфейса.
// Используется если getDefaultGateway вернул пустой шлюз но имя интерфейса известно.
func getInterfaceGateway(ifaceName string) string {
	cmd := hiddenCmd("powershell", "-NoProfile", "-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '"+ifaceName+"'|Select-Object -First 1|ForEach-Object{[string]$_.NextHop}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	gw := strings.TrimSpace(string(out))
	if gw != "" && net.ParseIP(gw) != nil {
		return gw
	}
	return ""
}

// addHostRoute добавляет маршрут /32 для targetIP через указанный интерфейс и шлюз.
func addHostRoute(iface, gateway, targetIP string) error {
	_ = runNetsh("interface", "ipv4", "delete", "route", targetIP+"/32", iface, "store=active")
	return runNetsh("interface", "ipv4", "add", "route", targetIP+"/32", iface, gateway, "metric=0", "store=active")
}

func runNetsh(args ...string) error {
	// Retry при ERROR_NOT_FOUND (0x00000490): после tun.CreateTUN() Windows
	// регистрирует адаптер в своём стеке с задержкой ~100-500мс, и netsh,
	// вызванный сразу после Up(), может не найти адаптер по имени.
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		cmd := hiddenCmd("netsh", args...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("netsh %v failed: %w; output=%s",
			strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		// Ретраим только если адаптер ещё не зарегистрирован.
		// Другие ошибки (access denied, invalid args) ретраить бессмысленно.
		if !strings.Contains(string(output), "0x00000490") {
			return lastErr
		}
		if attempt < maxAttempts-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return lastErr
}

// runRouteAdd добавляет статический маршрут через указанный шлюз.
// Использует route.exe вместо netsh, потому что:
//   - не требует повышения прав при наличии admin manifest
//   - работает одинаково и на старых, и на новых Windows
//   - не падает на длинных route-таблицах
//
// Возвращает true если маршрут успешно добавлен.
func runRouteAdd(cidr, gateway string) bool {
	cmd := hiddenCmd("route", "add", cidr, gateway, "metric", "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[EXCL] route add %s via %s: %v — %s", cidr, gateway, err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// runRouteDelete удаляет ранее добавленный маршрут. Ошибки игнорируются
// (маршрут мог быть удалён вручную или не существовать).
func runRouteDelete(cidr string) {
	cmd := hiddenCmd("route", "delete", cidr)
	_ = cmd.Run()
}

func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	target := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if fileExists(target) {
		return nil
	}

	if len(wintunEmbedded) > 0 {
		if err := os.WriteFile(target, wintunEmbedded, 0644); err == nil {
			log.Printf("[WG] Извлечён встроенный wintun.dll (%d KB) → %s", len(wintunEmbedded)/1024, target)
			return nil
		}
	}

	// Искать установленный WireGuard/Happ или System32
	candidates := findWintunDLLs()
	for _, src := range candidates {
		if err := copyFile(src, target); err == nil {
			log.Printf("[WG] Скопирован wintun.dll из %s", src)
			return nil
		}
	}

	return fmt.Errorf("wintun.dll не найден. Переустановите wdtt или установите WireGuard for Windows")
}

func findWintunDLLs() []string {
	var paths []string
	progFiles := os.Getenv("ProgramFiles")
	progFilesX86 := os.Getenv("ProgramFiles(x86)")
	if progFiles != "" {
		paths = append(paths,
			filepath.Join(progFiles, "WireGuard", "wintun.dll"),
			filepath.Join(progFiles, "WireGuard", "bin", "wintun.dll"),
			filepath.Join(progFiles, "WireGuard", "wintun.dll"),
			filepath.Join(progFiles, "Happ", "core", "wintun.dll"),
			filepath.Join(progFiles, "Happ", "tun2", "wintun.dll"),
		)
	}
	if progFilesX86 != "" {
		paths = append(paths,
			filepath.Join(progFilesX86, "WireGuard", "wintun.dll"),
			filepath.Join(progFilesX86, "WireGuard", "bin", "wintun.dll"),
			filepath.Join(progFilesX86, "Happ", "core", "wintun.dll"),
			filepath.Join(progFilesX86, "Happ", "tun2", "wintun.dll"),
		)
	}
	paths = append(paths,
		`C:\Program Files\WireGuard\wintun.dll`,
		`C:\Program Files\WireGuard\bin\wintun.dll`,
		`C:\Program Files\FlyFrogLLC\Happ\core\wintun.dll`,
		`C:\Program Files\FlyFrogLLC\Happ\tun2\wintun.dll`,
		`C:\Program Files (x86)\WireGuard\wintun.dll`,
		`C:\Windows\System32\wintun.dll`,
		`C:\Windows\SysWOW64\wintun.dll`,
	)
	var result []string
	for _, p := range paths {
		if fileExists(p) {
			result = append(result, p)
		}
	}
	return result
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}
