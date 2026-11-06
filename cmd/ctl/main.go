// wdtt — консольное управление запущенным WDTT (собирается в cli\wdtt.exe).
//
// Нужна на случай, когда окно недоступно или связь пропала: переключиться на
// другой сервер, переподключиться, посмотреть лог. Работает без прав
// администратора: говорит с приложением через именованный канал, а если оно
// не запущено — запускает его задачей планировщика (см. scripts/install.ps1).
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"wdtt-desktop/control"
)

const usage = `WDTT — управление туннелем из консоли

  wdtt                  состояние (то же, что status)
  wdtt status           подключено ли, к какому серверу, сколько воркеров
  wdtt servers          список серверов
  wdtt switch [сервер]  переключиться на другой сервер (без имени — на следующий)
  wdtt reconnect        переподключиться к текущему серверу
  wdtt start [сервер]   подключиться (запустит приложение, если оно закрыто)
  wdtt stop             отключить туннель
  wdtt check            проверить связь: туннель, сервер, интернет
  wdtt logs [N]         последние N строк лога сессии (по умолчанию 40)
  wdtt show             показать окно
  wdtt restart          перезапустить приложение (если зависло) и подключиться

Сервер можно назвать именем профиля или адресом (203.0.113.10).

Если связи нет:  wdtt check  →  wdtt switch  →  wdtt logs
`

func main() {
	args := os.Args[1:]
	cmd := "status"
	if len(args) > 0 {
		cmd = strings.ToLower(args[0])
		args = args[1:]
	}
	arg := strings.Join(args, " ")
	var code int
	switch cmd {
	case "status", "st":
		code = cmdStatus()
	case "servers", "list", "ls":
		code = cmdServers()
	case "switch", "sw":
		code = cmdConnect(control.CmdSwitch, arg)
	case "reconnect", "rc":
		code = cmdConnect(control.CmdReconnect, "")
	case "start", "connect", "up":
		code = cmdConnect(control.CmdStart, arg)
	case "stop", "down", "disconnect":
		code = cmdSimple(control.CmdStop)
	case "show":
		code = cmdSimple(control.CmdShow)
	case "check":
		code = cmdCheck()
	case "logs", "log":
		code = cmdLogs(arg)
	case "restart":
		code = cmdRestart(arg)
	case "help", "-h", "--help", "/?":
		fmt.Print(usage)
	default:
		fmt.Printf("Неизвестная команда «%s».\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}

func call(req control.Request, timeout time.Duration) (control.Response, bool) {
	resp, err := control.Call(req, timeout)
	if err != nil {
		return resp, false
	}
	return resp, true
}

func cmdStatus() int {
	resp, up := call(control.Request{Cmd: control.CmdStatus}, 10*time.Second)
	if !up {
		fmt.Println("Приложение WDTT не запущено (или не отвечает).")
		fmt.Println("Запустить и подключиться:  wdtt start")
		return 1
	}
	printStatus(resp.Status)
	if resp.Status.State != control.StateConnected {
		return 1
	}
	return 0
}

var stateRu = map[string]string{
	control.StateDisconnected: "отключено",
	control.StateConnecting:   "подключается…",
	control.StateConnected:    "подключено",
	control.StateStalled:      "туннель поднят, но живых воркеров нет",
	control.StateReconnecting: "ждёт переподключения",
}

func printStatus(st *control.Status) {
	if st == nil {
		return
	}
	fmt.Printf("Состояние: %s\n", stateRu[st.State])
	if st.Profile != "" {
		srv := st.Profile
		if st.Peer != "" && st.Peer != st.Profile {
			srv += " (" + st.Peer + ")"
		}
		fmt.Printf("Сервер:    %s\n", srv)
	}
	if st.State == control.StateConnected || st.State == control.StateStalled {
		fmt.Printf("Воркеры:   %d\n", st.Workers)
		fmt.Printf("Трафик:    ↓ %s  ↑ %s\n", human(st.RxBytes), human(st.TxBytes))
	}
	if t, err := time.Parse(time.RFC3339, st.UpSince); err == nil {
		fmt.Printf("Работает:  %s (с %s)\n", time.Since(t).Round(time.Second), t.Format("02.01 15:04"))
	}
	if st.Version != "" {
		fmt.Printf("Версия:    %s\n", st.Version)
	}
}

func human(b int64) string {
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.1f МБ", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.1f КБ", float64(b)/k)
	}
	return fmt.Sprintf("%d Б", b)
}

// cmdServers читает профили с диска — работает и без запущенного приложения.
func cmdServers() int {
	current := ""
	if resp, up := call(control.Request{Cmd: control.CmdStatus}, 5*time.Second); up && resp.Status != nil {
		current = resp.Status.Profile
	}
	profiles := readProfiles()
	if len(profiles) == 0 {
		fmt.Println("Серверов нет: добавьте сервер в окне приложения.")
		return 1
	}
	for _, p := range profiles {
		mark := "  "
		if p.Name == current {
			mark = "* "
		}
		if p.Peer != "" && p.Peer != p.Name {
			fmt.Printf("%s%s  (%s)\n", mark, p.Name, p.Peer)
		} else {
			fmt.Printf("%s%s\n", mark, p.Name)
		}
	}
	if current != "" {
		fmt.Println("\n* — текущий")
	}
	return 0
}

func readProfiles() []control.ProfileInfo {
	dir := filepath.Join(control.ConfigDir(), "profiles")
	entries, _ := os.ReadDir(dir)
	var out []control.ProfileInfo
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		info := control.ProfileInfo{Name: strings.TrimSuffix(name, ".json")}
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if i := strings.Index(string(b), `"peer"`); i >= 0 {
				rest := string(b[i+len(`"peer"`):])
				if q1 := strings.Index(rest, `"`); q1 >= 0 {
					if q2 := strings.Index(rest[q1+1:], `"`); q2 >= 0 {
						info.Peer = rest[q1+1 : q1+1+q2]
					}
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func cmdSimple(cmd string) int {
	resp, up := call(control.Request{Cmd: cmd}, 30*time.Second)
	if !up {
		fmt.Println("Приложение WDTT не запущено.")
		return 1
	}
	return report(resp)
}

func report(resp control.Response) int {
	if !resp.OK {
		fmt.Println("Ошибка:", resp.Error)
		return 1
	}
	if resp.Message != "" {
		fmt.Println(resp.Message)
	}
	return 0
}

// cmdConnect — switch / reconnect / start. Если приложение не запущено,
// запускает его с просьбой подключиться и ждёт подключения.
func cmdConnect(cmd, profile string) int {
	resp, up := call(control.Request{Cmd: cmd, Profile: profile}, 90*time.Second)
	if !up {
		if cmd == control.CmdReconnect {
			profile = ""
		}
		if profile != "" && !profileExists(profile) {
			fmt.Printf("Нет сервера «%s». Список: wdtt servers\n", profile)
			return 1
		}
		fmt.Println("Приложение не запущено — запускаю…")
		if err := launchApp(profile); err != nil {
			fmt.Println("Не удалось запустить:", err)
			return 1
		}
		return waitConnected(90 * time.Second)
	}
	if code := report(resp); code != 0 {
		return code
	}
	return waitConnected(90 * time.Second)
}

func profileExists(name string) bool {
	for _, p := range readProfiles() {
		if strings.EqualFold(p.Name, name) || p.Peer == name || strings.HasPrefix(p.Peer, name+":") {
			return true
		}
	}
	return false
}

// waitConnected печатает смену состояний, пока туннель не поднимется.
func waitConnected(timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		resp, up := call(control.Request{Cmd: control.CmdStatus}, 5*time.Second)
		if up && resp.Status != nil {
			st := resp.Status
			if st.State != last {
				fmt.Printf("  %s %s\n", time.Now().Format("15:04:05"), stateRu[st.State])
				last = st.State
			}
			if st.State == control.StateConnected {
				fmt.Println()
				printStatus(st)
				return 0
			}
		}
		time.Sleep(time.Second)
	}
	fmt.Println("\nНе подключилось за", timeout, "— попробуйте другой сервер (wdtt switch) или посмотрите лог (wdtt logs).")
	return 1
}

func cmdCheck() int {
	ok := true
	st, up := call(control.Request{Cmd: control.CmdStatus}, 5*time.Second)
	if !up {
		fmt.Println("✗ приложение не запущено")
		ok = false
	} else {
		mark := "✓"
		if st.Status.State != control.StateConnected {
			mark, ok = "✗", false
		}
		fmt.Printf("%s приложение: %s, воркеров %d\n", mark, stateRu[st.Status.State], st.Status.Workers)
	}
	if err := hidden("ping.exe", "-n", "2", "-w", "2000", "10.66.66.1").Run(); err != nil {
		fmt.Println("✗ сервер внутри туннеля (10.66.66.1) не отвечает")
		ok = false
	} else {
		fmt.Println("✓ сервер внутри туннеля отвечает")
	}
	cl := &http.Client{Timeout: 10 * time.Second}
	if r, err := cl.Get("https://api.ipify.org"); err != nil {
		fmt.Println("✗ интернет:", err)
		ok = false
	} else {
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		r.Body.Close()
		fmt.Printf("✓ интернет есть, внешний адрес %s\n", strings.TrimSpace(string(b[:n])))
	}
	if !ok {
		fmt.Println("\nДальше: wdtt switch (другой сервер) или wdtt restart (если приложение зависло).")
		return 1
	}
	return 0
}

func cmdLogs(arg string) int {
	n := 40
	if v, err := strconv.Atoi(strings.TrimSpace(arg)); err == nil && v > 0 {
		n = v
	}
	path := ""
	if resp, up := call(control.Request{Cmd: control.CmdStatus}, 5*time.Second); up && resp.Status != nil {
		path = resp.Status.LogFile
	}
	if path == "" {
		path = newestLog()
	}
	if path == "" {
		fmt.Println("Логов нет.")
		return 1
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("Не открыть лог:", err)
		return 1
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	fmt.Println("Лог:", path)
	for _, l := range lines {
		fmt.Println(l)
	}
	return 0
}

func newestLog() string {
	dir := filepath.Join(control.ConfigDir(), "logs")
	entries, _ := os.ReadDir(dir)
	best, bestT := "", time.Time{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".log") || e.Name() == "crash.log" {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(bestT) {
			best, bestT = filepath.Join(dir, e.Name()), fi.ModTime()
		}
	}
	return best
}

// cmdRestart закрывает приложение (или снимает зависшее) и запускает заново
// с подключением.
func cmdRestart(profile string) int {
	if _, up := call(control.Request{Cmd: control.CmdQuit}, 10*time.Second); up {
		fmt.Println("Закрываю приложение…")
		for i := 0; i < 30 && appAnswers(); i++ {
			time.Sleep(time.Second)
		}
	}
	if pids := guiPIDs(); len(pids) > 0 {
		fmt.Println("Приложение не закрылось — снимаю процесс (Windows спросит разрешение)…")
		args := []string{"/f"}
		for _, p := range pids {
			args = append(args, "/pid", strconv.Itoa(int(p)))
		}
		if err := runAs("taskkill.exe", strings.Join(args, " ")); err != nil {
			fmt.Println("Не удалось:", err)
			return 1
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("Запускаю…")
	if err := launchApp(profile); err != nil {
		fmt.Println("Не удалось запустить:", err)
		return 1
	}
	return waitConnected(90 * time.Second)
}

func appAnswers() bool {
	_, up := call(control.Request{Cmd: control.CmdStatus}, 2*time.Second)
	return up
}

// guiExe — приложение лежит на уровень выше папки cli.
func guiExe() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Dir(self)), "wdtt.exe")
}

// guiPIDs — процессы wdtt.exe, кроме этой утилиты (она тоже wdtt.exe).
func guiPIDs() []uint32 {
	self, _ := os.Executable()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []uint32
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), "wdtt.exe") || pe.ProcessID == uint32(os.Getpid()) {
			continue
		}
		if path := processPath(pe.ProcessID); path != "" && strings.EqualFold(path, self) {
			continue // другая копия этой утилиты
		}
		out = append(out, pe.ProcessID)
	}
	return out
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "" // процесс с правами администратора — путь не прочитать
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// launchApp просит приложение подключиться при запуске и запускает его:
// задачей планировщика (без UAC) или, если задачи нет, через UAC.
func launchApp(profile string) error {
	_ = os.MkdirAll(control.ConfigDir(), 0755)
	if err := os.WriteFile(control.PendingConnectPath(), []byte(profile), 0600); err != nil {
		return err
	}
	if err := hidden("schtasks.exe", "/run", "/tn", control.TaskName).Run(); err == nil {
		return nil
	}
	exe := guiExe()
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("нет задачи планировщика %q и не найден %s — переустановите (scripts\\install.ps1)", control.TaskName, exe)
	}
	return runAs(exe, "")
}

func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}

func runAs(exe, args string) error {
	if os.Getenv("WDTT_NO_ELEVATE") == "1" { // отладка: никогда не спрашивать UAC
		return fmt.Errorf("нужны права администратора (WDTT_NO_ELEVATE=1): %s %s", exe, args)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
}
