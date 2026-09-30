package core

// turnprobe.go — диагностика: что именно VK TURN relay пропускает.
//
// Поднимаются две аллокации (A и B) на TURN-серверах VK, и A шлёт в relay-адрес B
// пакеты разной формы (голые байты, RTP разных вариантов, DTLS) и разного
// размера. По тому, что доходит до B, видно, какой фильтр включил VK, без
// участия нашего VPS.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

type probeShape struct {
	Name  string
	Build func(size int, st *probeRTPState) []byte
}

type probeRTPState struct {
	ssrc  uint32
	seq   uint16
	ts    uint32
	start time.Time
	// wallClock — timestamp по реальному времени (как у настоящего WebRTC),
	// иначе +960 на каждый пакет (как в текущем obfs).
	wallClock bool
	tsBase    uint32
}

func newProbeRTPState(wallClock bool) *probeRTPState {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return &probeRTPState{
		ssrc:      binary.BigEndian.Uint32(b[0:4]),
		seq:       binary.BigEndian.Uint16(b[4:6]),
		ts:        binary.BigEndian.Uint32(b[6:10]),
		tsBase:    binary.BigEndian.Uint32(b[6:10]),
		start:     time.Now(),
		wallClock: wallClock,
	}
}

func (s *probeRTPState) next(clock uint32) (uint16, uint32) {
	s.seq++
	if s.wallClock {
		el := time.Since(s.start)
		s.ts = s.tsBase + uint32(el.Nanoseconds()*int64(clock)/int64(time.Second))
	} else {
		s.ts += 960
	}
	return s.seq, s.ts
}

func probeRandom(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// buildProbeRTP собирает RTP-пакет общей длины size.
// ext — one-byte header extension (abs-send-time + transport-cc, как в Chrome).
func buildProbeRTP(size int, st *probeRTPState, pt uint8, ext, padding bool) []byte {
	clock := uint32(48000)
	if pt == 96 {
		clock = 90000
	}
	seq, ts := st.next(clock)
	hdrLen := 12
	if ext {
		hdrLen = 24
	}
	if size < hdrLen+2 {
		size = hdrLen + 2
	}
	out := probeRandom(size)
	out[0] = 0x80
	if padding {
		out[0] |= 0x20
	}
	if ext {
		out[0] |= 0x10
	}
	out[1] = pt & 0x7F
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], st.ssrc)
	if ext {
		binary.BigEndian.PutUint16(out[12:14], 0xBEDE)
		binary.BigEndian.PutUint16(out[14:16], 2)
		abs := uint32(time.Since(st.start).Nanoseconds()*262144/int64(time.Second)) & 0xFFFFFF
		out[16] = 0x32
		out[17], out[18], out[19] = byte(abs>>16), byte(abs>>8), byte(abs)
		out[20] = 0x51
		binary.BigEndian.PutUint16(out[21:23], seq)
		out[23] = 0
	}
	if padding {
		pad := 1 + int(out[size-1])%16
		if pad > size-hdrLen-1 {
			pad = 1
		}
		out[size-1] = byte(pad)
	}
	return out
}

// buildProbeProduction — ровно то, что сейчас шлёт клиент (obfsWrapPacket).
func buildProbeProduction(size int, key []byte, cfg *ObfsConfig, state *ObfsState) []byte {
	// overhead obfs: 12 hdr + 16 tag + 1..PaddingMax
	plainLen := size - 12 - 16 - cfg.PaddingMax/2
	if plainLen < 1 {
		plainLen = 1
	}
	out, err := obfsWrapPacket(key, probeRandom(plainLen), cfg, state)
	if err != nil {
		return probeRandom(size)
	}
	return out
}

func probeShapes() []probeShape {
	key := probeRandom(wrapKeyLen)
	prodCfg := NewObfsConfig()
	prodState := NewObfsState()
	s111 := newProbeRTPState(false)
	s111w := newProbeRTPState(true)
	s111e := newProbeRTPState(true)
	s96 := newProbeRTPState(true)
	s96e := newProbeRTPState(true)
	return []probeShape{
		{"plain", func(n int, _ *probeRTPState) []byte { return probeRandom(n) }},
		{"dtls", func(n int, _ *probeRTPState) []byte {
			b := probeRandom(n)
			b[0], b[1], b[2] = 0x17, 0xFE, 0xFD
			if n >= 13 {
				binary.BigEndian.PutUint16(b[11:13], uint16(n-13))
			}
			return b
		}},
		{"wdtt-current", func(n int, _ *probeRTPState) []byte { return buildProbeProduction(n, key, prodCfg, prodState) }},
		{"rtp111-P", func(n int, _ *probeRTPState) []byte { return buildProbeRTP(n, s111, 111, false, true) }},
		{"rtp111-wall", func(n int, _ *probeRTPState) []byte { return buildProbeRTP(n, s111w, 111, false, false) }},
		{"rtp111-ext", func(n int, _ *probeRTPState) []byte { return buildProbeRTP(n, s111e, 111, true, false) }},
		{"rtp96", func(n int, _ *probeRTPState) []byte { return buildProbeRTP(n, s96, 96, false, false) }},
		{"rtp96-ext", func(n int, _ *probeRTPState) []byte { return buildProbeRTP(n, s96e, 96, true, false) }},
	}
}

var probeSizes = []int{60, 150, 300, 600, 900, 1100, 1200, 1300, 1400}

type probeRecv struct {
	count atomic.Int64
	bytes atomic.Int64
}

func probeAllocate(addr, user, pass string) (*turn.Client, net.PacketConn, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetReadBuffer(socketBufSize)
	_ = c.SetWriteBuffer(socketBufSize)
	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr,
		TURNServerAddr: addr,
		Conn:           &connectedUDPConn{c},
		Username:       user,
		Password:       pass,
		LoggerFactory:  &NullLoggerFactory{},
	})
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	if err := tc.Listen(); err != nil {
		tc.Close()
		_ = c.Close()
		return nil, nil, err
	}
	relay, err := tc.Allocate()
	if err != nil {
		tc.Close()
		_ = c.Close()
		return nil, nil, err
	}
	return tc, relay, nil
}

// TurnProbeCreds — TURN-креды для пробы (если пусто — берутся по хешу).
type TurnProbeCreds struct {
	User, Pass string
	Addrs      []string
}

// RunTurnProbe получает TURN-креды по хешу звонка и проверяет, какие пакеты
// VK relay пересылает между двумя аллокациями. Отчёт пишется в out.
func RunTurnProbe(ctx context.Context, hash string, creds *TurnProbeCreds, out io.Writer) error {
	p := func(format string, a ...interface{}) { fmt.Fprintf(out, format+"\n", a...) }

	if creds == nil {
		setupGlobalResolver()
		u, pw, addrs, err := GetCreds(ctx, hash, 0)
		if err != nil {
			return fmt.Errorf("получение TURN кредов: %w", err)
		}
		creds = &TurnProbeCreds{User: u, Pass: pw, Addrs: addrs}
	}
	if len(creds.Addrs) == 0 {
		return fmt.Errorf("нет TURN адресов")
	}
	p("TURN серверы: %s", strings.Join(creds.Addrs, ", "))

	type pair struct{ a, b string }
	pairs := []pair{{creds.Addrs[0], creds.Addrs[0]}}
	if len(creds.Addrs) > 1 {
		pairs = append(pairs, pair{creds.Addrs[0], creds.Addrs[1]})
	}

	for _, pr := range pairs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p("")
		p("══ A=%s → B=%s ══", pr.a, pr.b)
		if err := runProbePair(ctx, pr.a, pr.b, creds, p); err != nil {
			p("ОШИБКА: %v", err)
		}
	}
	return nil
}

func runProbePair(ctx context.Context, addrA, addrB string, creds *TurnProbeCreds, p func(string, ...interface{})) error {
	tcA, ra, err := probeAllocate(addrA, creds.User, creds.Pass)
	if err != nil {
		return fmt.Errorf("allocate A: %w", err)
	}
	defer tcA.Close()
	defer ra.Close()
	tcB, rb, err := probeAllocate(addrB, creds.User, creds.Pass)
	if err != nil {
		return fmt.Errorf("allocate B: %w", err)
	}
	defer tcB.Close()
	defer rb.Close()
	p("relay A=%s  relay B=%s", ra.LocalAddr(), rb.LocalAddr())

	var recvB, recvA probeRecv
	var wg sync.WaitGroup
	reader := func(c net.PacketConn, r *probeRecv) {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			r.count.Add(1)
			r.bytes.Add(int64(n))
		}
	}
	wg.Add(2)
	go reader(rb, &recvB)
	go reader(ra, &recvA)
	defer func() {
		_ = ra.SetDeadline(time.Now())
		_ = rb.SetDeadline(time.Now())
		wg.Wait()
	}()

	// Разрешения в обе стороны: первая запись создаёт CreatePermission (+ ChannelBind).
	warm := buildProbeRTP(100, newProbeRTPState(true), 111, false, false)
	if _, err := rb.WriteTo(warm, ra.LocalAddr()); err != nil {
		return fmt.Errorf("permission B→A: %w", err)
	}
	if _, err := ra.WriteTo(warm, rb.LocalAddr()); err != nil {
		return fmt.Errorf("permission A→B: %w", err)
	}
	time.Sleep(700 * time.Millisecond)

	// Обратное направление (B→A) — просто проверка, что оно живое вообще.
	recvA.count.Store(0)
	for i := 0; i < 5; i++ {
		_, _ = rb.WriteTo(buildProbeRTP(200, newProbeRTPState(true), 111, false, false), ra.LocalAddr())
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(800 * time.Millisecond)
	p("B→A rtp111 200B: %d/5", recvA.count.Load())

	const perCell = 5
	shapes := probeShapes()
	header := fmt.Sprintf("%-14s", "форма\\размер")
	for _, sz := range probeSizes {
		header += fmt.Sprintf("%6d", sz)
	}
	p("%s", header)
	for _, sh := range shapes {
		line := fmt.Sprintf("%-14s", sh.Name)
		for _, sz := range probeSizes {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			recvB.count.Store(0)
			for i := 0; i < perCell; i++ {
				_, _ = ra.WriteTo(sh.Build(sz, nil), rb.LocalAddr())
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(600 * time.Millisecond)
			line += fmt.Sprintf("%6s", fmt.Sprintf("%d/%d", recvB.count.Load(), perCell))
		}
		p("%s", line)
	}

	// Burst: поток крупных пакетов как при загрузке страницы.
	for _, sh := range shapes {
		if sh.Name != "wdtt-current" && sh.Name != "rtp111-wall" && sh.Name != "rtp96-ext" && sh.Name != "rtp111-ext" {
			continue
		}
		for _, sz := range []int{300, 1200} {
			const burst = 400
			recvB.count.Store(0)
			start := time.Now()
			for i := 0; i < burst; i++ {
				_, _ = ra.WriteTo(sh.Build(sz, nil), rb.LocalAddr())
				if i%20 == 19 {
					time.Sleep(2 * time.Millisecond)
				}
			}
			el := time.Since(start)
			time.Sleep(1200 * time.Millisecond)
			got := recvB.count.Load()
			p("burst %-12s %4dB: %d/%d за %v (~%.1f Мбит/с отправка)", sh.Name, sz, got, burst, el.Truncate(time.Millisecond),
				float64(burst*sz*8)/el.Seconds()/1e6)
		}
	}

	// Долгая сессия: не режет ли VK поток через N секунд.
	recvB.count.Store(0)
	st := newProbeRTPState(true)
	sent := 0
	for i := 0; i < 15*25; i++ { // 15 с, 25 пакетов/с
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, _ = ra.WriteTo(buildProbeRTP(1000, st, 111, false, false), rb.LocalAddr())
		sent++
		time.Sleep(40 * time.Millisecond)
		if sent%125 == 0 {
			p("поток rtp111-wall 1000B, %2d c: %d/%d", sent/25, recvB.count.Load(), sent)
		}
	}
	return nil
}
