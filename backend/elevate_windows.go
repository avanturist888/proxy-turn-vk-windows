//go:build windows

package backend

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"wdtt-desktop/control"
)

// HandOffIfNotElevated вызывается до запуска UI. Туннелю нужны права
// администратора (адаптер wintun, маршруты, DNS), но запрашивать UAC при
// каждом запуске не нужно: scripts/install.ps1 регистрирует задачу
// планировщика с наивысшими правами, и обычный запуск передаёт ей работу.
//
// Возвращает true, если этот процесс должен просто выйти:
//   - приложение уже запущено — показали его окно;
//   - задача планировщика запустила копию с правами;
//   - задачи нет — запросили права через UAC (один раз, как раньше всегда).
//
// WDTT_NO_ELEVATE=1 — запуск без всего этого (отладка).
func HandOffIfNotElevated() bool {
	if !handOffEnabled || os.Getenv("WDTT_NO_ELEVATE") == "1" || windows.GetCurrentProcessToken().IsElevated() {
		return false
	}
	if _, err := control.Call(control.Request{Cmd: control.CmdShow}, 3*time.Second); err == nil {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if taskRunsExe(control.TaskName, exe) && runTask(control.TaskName) == nil {
		return true
	}
	if err := shellRunAs(exe, strings.Join(quoteArgs(os.Args[1:]), " ")); err != nil {
		if err != windows.ERROR_CANCELLED {
			msg, _ := windows.UTF16PtrFromString("WDTT нужны права администратора, а запросить их не удалось: " + err.Error())
			title, _ := windows.UTF16PtrFromString("WDTT")
			windows.MessageBox(0, msg, title, windows.MB_OK|windows.MB_ICONWARNING)
		}
	}
	return true
}

func hiddenCmd(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}

var taskCommandRe = regexp.MustCompile(`<Command>([^<]+)</Command>`)

// taskRunsExe — есть ли задача и запускает ли она именно этот exe (иначе
// отладочная сборка из build\bin молча запускала бы установленную).
func taskRunsExe(task, exe string) bool {
	out, err := hiddenCmd("schtasks.exe", "/query", "/tn", task, "/xml", "ONE").Output()
	if err != nil {
		return false
	}
	m := taskCommandRe.FindStringSubmatch(decodeMaybeUTF16(out))
	if m == nil {
		return false
	}
	cmd := strings.Trim(strings.TrimSpace(m[1]), `"`)
	return strings.EqualFold(filepath.Clean(os.ExpandEnv(cmd)), filepath.Clean(exe))
}

func runTask(task string) error {
	return hiddenCmd("schtasks.exe", "/run", "/tn", task).Run()
}

func shellRunAs(exe, args string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL)
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = syscall.EscapeArg(a)
	}
	return out
}

// decodeMaybeUTF16 — schtasks отдаёт XML то в UTF-16LE, то в однобайтовой
// кодировке, смотря куда направлен вывод.
func decodeMaybeUTF16(b []byte) string {
	if len(b) >= 2 && (b[0] == 0xFF && b[1] == 0xFE || len(b) > 4 && b[1] == 0 && b[3] == 0) {
		if b[0] == 0xFF && b[1] == 0xFE {
			b = b[2:]
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}
