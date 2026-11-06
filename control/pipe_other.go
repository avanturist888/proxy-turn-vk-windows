//go:build !windows

package control

import (
	"errors"
	"net"
	"time"
)

var errUnsupported = errors.New("канал управления есть только в Windows-сборке")

func dial(string, time.Duration) (net.Conn, error) { return nil, errUnsupported }

func Listen() (net.Listener, error) { return nil, errUnsupported }
