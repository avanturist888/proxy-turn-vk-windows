// Package control — канал управления запущенным WDTT из консоли (wdtt.exe в
// папке cli). Приложение слушает именованный канал, консольная утилита шлёт
// одну JSON-строку запроса и читает одну JSON-строку ответа.
package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PipeName — имя канала; WDTT_PIPE переопределяет его (тесты, отладка).
func PipeName() string {
	if v := os.Getenv("WDTT_PIPE"); v != "" {
		return v
	}
	return `\\.\pipe\wdtt-control`
}

// Команды.
const (
	CmdStatus    = "status"
	CmdSwitch    = "switch"    // Profile: куда; пусто — на следующий профиль
	CmdReconnect = "reconnect" // переподключиться к текущему профилю
	CmdStart     = "start"     // Profile: к какому; пусто — к последнему
	CmdStop      = "stop"
	CmdShow      = "show" // показать окно
	CmdQuit      = "quit" // выйти из приложения
)

type Request struct {
	Cmd     string `json:"cmd"`
	Profile string `json:"profile,omitempty"`
}

type Response struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Message string  `json:"message,omitempty"`
	Status  *Status `json:"status,omitempty"`
}

// Состояния туннеля в Status.State.
const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateStalled      = "stalled" // туннель поднят, но живых воркеров нет
	StateReconnecting = "reconnecting"
)

type Status struct {
	State    string        `json:"state"`
	Profile  string        `json:"profile,omitempty"`
	Peer     string        `json:"peer,omitempty"`
	Workers  int32         `json:"workers"`
	RxBytes  int64         `json:"rx"`
	TxBytes  int64         `json:"tx"`
	UpSince  string        `json:"upSince,omitempty"` // RFC3339, когда туннель поднялся
	LogFile  string        `json:"logFile,omitempty"`
	Version  string        `json:"version,omitempty"`
	PID      int           `json:"pid"`
	Profiles []ProfileInfo `json:"profiles,omitempty"`
}

type ProfileInfo struct {
	Name string `json:"name"`
	Peer string `json:"peer"`
}

// Handler обрабатывает запрос в приложении.
type Handler func(Request) Response

// Serve обслуживает соединения слушателя до его закрытия.
func Serve(l net.Listener, h Handler) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go serveConn(c, h)
	}
}

func serveConn(c net.Conn, h Handler) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	var resp Response
	if err := json.Unmarshal(line, &req); err != nil {
		resp = Response{Error: "неверный запрос: " + err.Error()}
	} else {
		resp = safeHandle(h, req)
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

func safeHandle(h Handler, req Request) (resp Response) {
	defer func() {
		if r := recover(); r != nil {
			resp = Response{Error: fmt.Sprintf("внутренняя ошибка: %v", r)}
		}
	}()
	return h(req)
}

// Call отправляет запрос запущенному приложению. Ошибка соединения значит,
// что приложение не запущено (или зависло и не принимает соединения).
func Call(req Request, timeout time.Duration) (Response, error) {
	c, err := dial(PipeName(), 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("неверный ответ: %w", err)
	}
	return resp, nil
}

// ConfigDir — %APPDATA%\wdtt, общий для приложения и консольной утилиты.
func ConfigDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.Getenv("HOME")
	}
	return filepath.Join(base, "wdtt")
}

// PendingConnectPath — файл-просьба «подключиться при запуске»: консольная
// утилита пишет в него имя профиля (пусто — последний), запускает приложение,
// приложение при старте подключается и удаляет файл.
func PendingConnectPath() string { return filepath.Join(ConfigDir(), "pending_connect") }

// TaskName — задача планировщика, которая запускает приложение с правами
// администратора без запроса UAC (создаёт scripts/install.ps1).
const TaskName = "WDTT"
