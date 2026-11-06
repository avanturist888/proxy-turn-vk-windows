package backend

import (
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"wdtt-desktop/control"
)

// startControl открывает канал управления для консольной утилиты (wdtt.exe
// в папке cli) и выполняет отложенную просьбу «подключиться при запуске».
func (a *App) startControl() {
	l, err := control.Listen()
	if err != nil {
		log.Printf("[CTL] Канал управления не открыт: %v", err)
	} else {
		go control.Serve(l, a.handleControl)
	}
	a.connectIfRequested()
}

// ConnectFlag — ключ командной строки «подключиться при запуске»: с ним
// приложение ставит в автозапуск (после входа в Windows туннель
// поднимается сам, а не только открывается окно).
const ConnectFlag = "--connect"

// RequestConnectIfFlagged вызывается в main до передачи запуска задаче
// планировщика (она аргументов не передаёт): ключ --connect превращается в
// файл-просьбу pending_connect, которую прочитает запущенный экземпляр.
func RequestConnectIfFlagged(args []string) {
	for _, a := range args {
		if a == ConnectFlag {
			_ = os.MkdirAll(control.ConfigDir(), 0755)
			if _, err := os.Stat(control.PendingConnectPath()); err != nil {
				_ = os.WriteFile(control.PendingConnectPath(), nil, 0600)
			}
			return
		}
	}
}

// connectIfRequested — консольная утилита запустила приложение с просьбой
// подключиться (файл pending_connect с именем профиля, пусто — последний).
func (a *App) connectIfRequested() {
	path := control.PendingConnectPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = os.Remove(path)
	name := strings.TrimSpace(string(b))
	go func() {
		if err := a.orch.SwitchTo(name); err == errNoLastParams {
			// Параметров ещё нет — пусть подключит окно, как кнопкой. Окно
			// в этот момент может быть ещё не загружено, поэтому не событие,
			// а флаг: окно забирает его при загрузке (TakeConnectRequest).
			a.uiConnectRequested.Store(true)
		} else if err != nil {
			log.Printf("[CTL] Подключение при запуске не удалось: %v", err)
		}
	}()
}

// TakeConnectRequest — окно при загрузке спрашивает, просили ли подключиться
// при запуске (консольная утилита, установщик). Флаг одноразовый.
func (a *App) TakeConnectRequest() bool {
	return a.uiConnectRequested.Swap(false)
}

func (a *App) profileInfos() []control.ProfileInfo {
	all, _ := a.store.ListProfiles()
	out := make([]control.ProfileInfo, 0, len(all))
	for name, p := range all {
		out = append(out, control.ProfileInfo{Name: name, Peer: p.PeerAddr})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// nextProfile — профиль после current по алфавиту (по кругу).
func nextProfile(profiles []control.ProfileInfo, current string) (string, bool) {
	if len(profiles) < 2 {
		return "", false
	}
	for i, p := range profiles {
		if p.Name == current {
			return profiles[(i+1)%len(profiles)].Name, true
		}
	}
	return profiles[0].Name, true
}

func findProfile(profiles []control.ProfileInfo, name string) (string, bool) {
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) {
			return p.Name, true
		}
	}
	// Можно назвать сервер адресом: «203.0.113.10» или «203.0.113.10:3478».
	for _, p := range profiles {
		if p.Peer == name || strings.HasPrefix(p.Peer, name+":") {
			return p.Name, true
		}
	}
	return "", false
}

func (a *App) handleControl(req control.Request) control.Response {
	profiles := a.profileInfos()
	status := func() *control.Status {
		st := a.orch.Status()
		st.Profiles = profiles
		return &st
	}
	fail := func(msg string) control.Response { return control.Response{Error: msg, Status: status()} }
	ok := func(msg string) control.Response { return control.Response{OK: true, Message: msg, Status: status()} }

	switch req.Cmd {
	case control.CmdStatus:
		return ok("")

	case control.CmdSwitch, control.CmdStart, control.CmdReconnect:
		cur := a.orch.Status().Profile
		if cur == "" {
			if p, has := a.orch.LastParams(); has {
				cur = p.Profile
			}
		}
		target := ""
		switch {
		case req.Cmd == control.CmdReconnect:
			target = cur
		case req.Profile != "":
			name, found := findProfile(profiles, req.Profile)
			if !found {
				return fail("нет сервера «" + req.Profile + "» — список: wdtt servers")
			}
			target = name
		case req.Cmd == control.CmdSwitch:
			name, has := nextProfile(profiles, cur)
			if !has {
				return fail("сохранён только один сервер — переключаться некуда")
			}
			target = name
		}
		if req.Cmd == control.CmdStart && a.orch.IsRunning() && (target == "" || target == cur) {
			return ok("уже подключено или подключается")
		}
		runtime.EventsEmit(a.ctx, "log", "INFO", "[CTL] Команда из консоли: "+req.Cmd+" "+target)
		if err := a.orch.SwitchTo(target); err != nil {
			if err == errNoLastParams && req.Cmd == control.CmdStart {
				runtime.EventsEmit(a.ctx, "tray_request_connect")
				return ok("подключаю из окна (параметров прошлого подключения ещё нет)")
			}
			return fail(err.Error())
		}
		return ok("подключаюсь к " + displayName(profiles, target))

	case control.CmdStop:
		a.orch.Stop()
		return ok("туннель отключён")

	case control.CmdShow:
		runtime.WindowShow(a.ctx)
		runtime.WindowUnminimise(a.ctx)
		return ok("")

	case control.CmdQuit:
		go func() {
			time.Sleep(200 * time.Millisecond) // ответ успевает уйти
			if a.orch != nil {
				a.orch.Stop()
			}
			a.allowExit.Store(true)
			runtime.Quit(a.ctx)
		}()
		return ok("приложение закрывается")
	}
	return fail("неизвестная команда «" + req.Cmd + "»")
}

func displayName(profiles []control.ProfileInfo, name string) string {
	for _, p := range profiles {
		if p.Name == name && p.Peer != "" && p.Peer != name {
			return name + " (" + p.Peer + ")"
		}
	}
	return name
}
