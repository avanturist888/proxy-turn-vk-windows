//go:build windows

package control

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func dial(path string, timeout time.Duration) (net.Conn, error) {
	return namedpipe.DialTimeout(path, timeout)
}

// Listen открывает канал управления. Приложение работает с правами
// администратора, а консоль — обычно без них, поэтому доступ к каналу:
// SYSTEM и администраторы — полный, владелец процесса (тот же пользователь) —
// чтение и запись; метка целостности Medium, иначе процесс без повышения
// не сможет писать в канал процесса с High. Другие пользователи доступа
// не имеют.
func Listen() (net.Listener, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token user: %w", err)
	}
	sid := u.User.Sid.String()
	sddl := fmt.Sprintf("O:%sD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)S:(ML;;NW;;;ME)", sid, sid)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("security descriptor: %w", err)
	}
	cfg := namedpipe.ListenConfig{SecurityDescriptor: sd}
	return cfg.Listen(PipeName())
}
