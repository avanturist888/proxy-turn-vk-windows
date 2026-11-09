package core

import (
	"testing"
	"time"
)

func wgKeepalive() []byte {
	p := make([]byte, wgKeepaliveLen)
	p[0] = 4
	return p
}

func wgData(n int) []byte {
	p := make([]byte, n)
	p[0] = 4
	return p
}

func TestLivenessIdleIsNotDeath(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newLiveness(t0)
	// Простой: только keepalive WireGuard, сервер молчит.
	for i := 0; i < 20; i++ {
		l.sent(wgKeepalive(), t0.Add(time.Duration(i)*25*time.Second))
	}
	if dead, _ := l.dead(t0.Add(10*time.Minute), 45*time.Second); dead {
		t.Fatal("idle session with only WireGuard keepalives was declared dead")
	}
}

func TestLivenessUnansweredDataIsDeath(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newLiveness(t0)
	l.sent(wgData(120), t0.Add(time.Minute))
	if dead, _ := l.dead(t0.Add(time.Minute+40*time.Second), 45*time.Second); dead {
		t.Fatal("declared dead before the limit")
	}
	// Ещё пакеты не сдвигают начало ожидания.
	l.sent(wgData(120), t0.Add(time.Minute+44*time.Second))
	dead, silent := l.dead(t0.Add(time.Minute+46*time.Second), 45*time.Second)
	if !dead {
		t.Fatal("unanswered data for 46s: want dead")
	}
	if silent != 106*time.Second {
		t.Fatalf("silent = %v, want 1m46s", silent)
	}
}

func TestLivenessAnswerResets(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newLiveness(t0)
	l.sent(wgData(148), t0) // handshake initiation
	l.received(t0.Add(time.Second))
	if dead, _ := l.dead(t0.Add(time.Hour), 45*time.Second); dead {
		t.Fatal("answered session declared dead")
	}
	l.sent(wgData(80), t0.Add(time.Hour))
	if dead, _ := l.dead(t0.Add(time.Hour+46*time.Second), 45*time.Second); !dead {
		t.Fatal("new unanswered packet after an answer: want dead")
	}
}

func TestExpectsReply(t *testing.T) {
	if expectsReply(wgKeepalive()) {
		t.Error("WireGuard keepalive must not expect a reply")
	}
	if !expectsReply(wgData(148)) || !expectsReply(wgData(33)) {
		t.Error("data and handshake packets expect a reply")
	}
	p := make([]byte, wgKeepaliveLen)
	p[0] = 1
	if !expectsReply(p) {
		t.Error("32-byte non-transport message expects a reply")
	}
}

func TestDeniedReason(t *testing.T) {
	if r, ok := deniedReason([]byte("DENIED:device_mismatch")); !ok || r != "device_mismatch" {
		t.Fatalf("got %q %v", r, ok)
	}
	for _, p := range [][]byte{[]byte("DENIED:"), []byte("READY_OK"), {0x04, 0, 0, 0}, nil} {
		if _, ok := deniedReason(p); ok {
			t.Fatalf("%q must not be a denial", p)
		}
	}
}
