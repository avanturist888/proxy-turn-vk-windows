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
	l.sent(wgData(160), t0.Add(time.Minute))
	l.sent(wgData(160), t0.Add(time.Minute+time.Second))
	if dead, _ := l.dead(t0.Add(time.Minute+40*time.Second), 45*time.Second); dead {
		t.Fatal("declared dead before the limit")
	}
	// Ещё пакеты не сдвигают начало ожидания.
	l.sent(wgData(160), t0.Add(time.Minute+44*time.Second))
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
	for i := 0; i < minUnanswered; i++ {
		l.sent(wgData(1400), t0.Add(time.Hour))
	}
	if dead, _ := l.dead(t0.Add(time.Hour+46*time.Second), 45*time.Second); !dead {
		t.Fatal("new unanswered packet after an answer: want dead")
	}
}

func TestExpectsReply(t *testing.T) {
	if expectsReply(wgKeepalive()) {
		t.Error("WireGuard keepalive must not expect a reply")
	}
	if !expectsReply(wgData(148)) || !expectsReply(wgData(128)) {
		t.Error("data packets longer than a bare ACK expect a reply")
	}
	for _, n := range []int{80, 96, 112} {
		if expectsReply(wgData(n)) {
			t.Errorf("%d-byte transport packet (bare ACK size) must not expect a reply", n)
		}
	}
	hs := make([]byte, 148)
	hs[0] = 1
	if !expectsReply(hs) {
		t.Error("handshake initiation expects a reply")
	}
	p := make([]byte, wgKeepaliveLen)
	p[0] = 1
	if !expectsReply(p) {
		t.Error("32-byte non-transport message expects a reply")
	}
}

// Простой на worker: после ответа сервера клиент шлёт последний ACK, и
// больше ничего не приходит. Это не смерть.
func TestLivenessTrailingAckIsNotDeath(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newLiveness(t0)
	l.sent(wgData(400), t0)
	l.received(t0.Add(100 * time.Millisecond))
	l.sent(wgData(80), t0.Add(101*time.Millisecond)) // чистый ACK
	l.sent(wgData(96), t0.Add(2*time.Second))        // ACK с метками времени
	if dead, _ := l.dead(t0.Add(10*time.Minute), 45*time.Second); dead {
		t.Fatal("trailing bare ACKs declared the session dead")
	}
}

// Одиночный пакет с данными без ответа (UDP «в одну сторону») — тоже не смерть.
func TestLivenessSingleUnansweredIsNotDeath(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newLiveness(t0)
	l.sent(wgData(300), t0)
	if dead, _ := l.dead(t0.Add(10*time.Minute), 45*time.Second); dead {
		t.Fatal("one unanswered packet declared the session dead")
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
