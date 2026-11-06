package core

import (
	"context"
	"net"
	"testing"
	"time"
)

// Shutdown не должен зависеть от того, придёт ли ещё пакет на локальный
// порт: после снятия WG-интерфейса туда больше никто не пишет.
func TestDispatcherShutdownWithoutTraffic(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	d := NewDispatcher(context.Background(), conn, NewStats())
	done := make(chan struct{})
	go func() {
		d.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown завис: readLoop ждёт пакет на локальном порту")
	}
}
