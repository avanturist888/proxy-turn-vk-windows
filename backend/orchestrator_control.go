package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"wg-turn-client/core"
	"wdtt-desktop/control"
)

// Операции оркестратора для консольного управления (control).

var errNoLastParams = errors.New("приложение ещё ни разу не подключалось — подключитесь один раз из окна")

// releaseLog закрывает лог сессии и, если он ещё текущий, возвращает
// стандартный логгер на прежний вывод.
func (o *Orchestrator) releaseLog(lw *wailsLogWriter) {
	if lw == nil {
		return
	}
	if w, ok := log.Writer().(*wailsLogWriter); ok && w == lw {
		prev := o.prevLogWriter
		if prev == nil {
			prev = io.Discard
		}
		log.SetOutput(prev)
	}
	lw.close()
}

func lastParamsPath() string { return filepath.Join(configDir(), "last_connect.json") }

// rememberParams запоминает параметры подключения в памяти и на диске:
// по ним консольная утилита переключает сервер и подключается при запуске.
func (o *Orchestrator) rememberParams(p ConnectParams) {
	o.mu.Lock()
	o.lastParams = p
	o.hasLastParams = true
	o.mu.Unlock()
	b, err := json.MarshalIndent(p, "", " ")
	if err == nil {
		err = os.WriteFile(lastParamsPath(), b, 0600)
	}
	if err != nil {
		log.Printf("[CTL] Не удалось сохранить параметры подключения: %v", err)
	}
}

// LastParams — параметры последнего подключения (из памяти или с диска).
func (o *Orchestrator) LastParams() (ConnectParams, bool) {
	o.mu.Lock()
	if o.hasLastParams {
		p := o.lastParams
		o.mu.Unlock()
		return p, true
	}
	o.mu.Unlock()
	b, err := os.ReadFile(lastParamsPath())
	if err != nil {
		return ConnectParams{}, false
	}
	var p ConnectParams
	if json.Unmarshal(b, &p) != nil || p.Profile == "" {
		return ConnectParams{}, false
	}
	return p, true
}

// paramsForProfile — параметры прошлого подключения, перенаправленные на
// профиль name из profiles/. Разовые данные профиля подписки сбрасываем,
// иначе подключение ушло бы на прежний сервер.
func paramsForProfile(base ConnectParams, name string) ConnectParams {
	p := base
	if name == base.Profile && base.PeerAddr != "" {
		return p // тот же профиль подписки — данные остаются его
	}
	p.Profile = name
	p.PeerAddr, p.Password, p.Listen, p.TurnHost, p.TurnPort, p.DeviceID = "", "", "", "", "", ""
	p.PHashes = nil
	return p
}

// SwitchTo останавливает текущую сессию (если есть) и подключается к
// профилю name с параметрами прошлого подключения. name == "" — к
// последнему профилю.
func (o *Orchestrator) SwitchTo(name string) error {
	base, ok := o.LastParams()
	if !ok {
		return errNoLastParams
	}
	if name == "" {
		name = base.Profile
	}
	p := paramsForProfile(base, name)
	// Исключения по доменам — текущий список с диска, а не снимок прошлого
	// подключения: окно читает их при каждом подключении, консоль — тоже.
	if domains, err := core.LoadExcludeDomains(configDir()); err == nil {
		p.ExcludeDomains = domains
	}
	if p.PeerAddr == "" {
		if _, err := loadProfile(name); err != nil {
			return fmt.Errorf("нет профиля %q", name)
		}
	}
	o.mu.Lock()
	old := o.sess
	o.mu.Unlock()
	log.Printf("[CTL] Переключение на профиль %s", name)
	o.Stop()
	// Stop ждёт teardown не дольше 8 с; дождёмся его конца, чтобы новая
	// сессия не встретилась со снятием WG от старой.
	if old != nil && old.done != nil {
		select {
		case <-old.done:
		case <-time.After(20 * time.Second):
		}
	}
	if err := o.Start(p); err != nil {
		return err
	}
	runtime.EventsEmit(o.appCtx, "profile_switched", name)
	return nil
}

// Status — состояние туннеля для консольной утилиты.
func (o *Orchestrator) Status() control.Status {
	o.mu.Lock()
	sess := o.sess
	pending := o.reconnectPending
	pendingProfile := o.reconnectProfile
	o.mu.Unlock()

	st := control.Status{State: control.StateDisconnected, PID: os.Getpid(), Version: appVersion}
	switch {
	case sess == nil && pending:
		st.State = control.StateReconnecting
		st.Profile = pendingProfile
	case sess == nil:
	case sess.c == nil:
		st.State = control.StateConnecting
	default:
		st.Profile = sess.params.Profile
		st.Peer = sess.peer
		st.LogFile = sess.lw.path()
		snap := sess.c.Stats()
		st.Workers = snap.ActiveConnections
		st.RxBytes, st.TxBytes = snap.TotalBytesDown, snap.TotalBytesUp
		switch {
		case !sess.wasUp.Load():
			st.State = control.StateConnecting
		case snap.ActiveConnections > 0:
			st.State = control.StateConnected
			st.UpSince = time.Unix(sess.upAt.Load(), 0).Format(time.RFC3339)
		default:
			st.State = control.StateStalled
		}
	}
	return st
}
