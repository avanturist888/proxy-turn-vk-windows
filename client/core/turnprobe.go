package core

// turnprobe.go — диагностика VK TURN relay без участия VPS.
//
// Поднимаются две аллокации (A и B), A шлёт в relay-адрес B помеченные пакеты
// (номер теста, номер пакета, время отправки). По меткам видно не только,
// дошёл ли пакет, но и с какой задержкой — поздние пакеты не путаются с
// пакетами следующего теста.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v5"
)

const (
	probeTagLen = 16 // magic(4) cell(2) idx(2) sentNanos(8)
)

var probeMagic = [4]byte{'W', 'D', 'P', 'B'}

type probeShape struct {
	Name string
	// Build собирает пакет длины ~size с меткой tag внутри.
	Build func(size int, tag []byte) []byte
}

type probeRTPState struct {
	ssrc   uint32
	seq    uint16
	tsBase uint32
	start  time.Time
}

func newProbeRTPState() *probeRTPState {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return &probeRTPState{
		ssrc:   binary.BigEndian.Uint32(b[0:4]),
		seq:    binary.BigEndian.Uint16(b[4:6]),
		tsBase: binary.BigEndian.Uint32(b[6:10]),
		start:  time.Now(),
	}
}

func probeRandom(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// buildProbeRTP: RTP-пакет длины size, метка сразу после заголовка.
// ext — one-byte header extension (abs-send-time + transport-cc, как у Chrome).
func buildProbeRTP(size int, tag []byte, st *probeRTPState, pt uint8, ext bool) []byte {
	clock := int64(48000)
	if pt == 96 {
		clock = 90000
	}
	st.seq++
	el := time.Since(st.start)
	ts := st.tsBase + uint32(el.Nanoseconds()*clock/int64(time.Second))
	hdrLen := 12
	if ext {
		hdrLen = 24
	}
	if size < hdrLen+len(tag) {
		size = hdrLen + len(tag)
	}
	out := probeRandom(size)
	out[0] = 0x80
	if ext {
		out[0] |= 0x10
	}
	out[1] = pt & 0x7F
	binary.BigEndian.PutUint16(out[2:4], st.seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], st.ssrc)
	if ext {
		binary.BigEndian.PutUint16(out[12:14], 0xBEDE)
		binary.BigEndian.PutUint16(out[14:16], 2)
		abs := uint32(el.Nanoseconds()*262144/int64(time.Second)) & 0xFFFFFF
		out[16] = 0x32
		out[17], out[18], out[19] = byte(abs>>16), byte(abs>>8), byte(abs)
		out[20] = 0x51
		binary.BigEndian.PutUint16(out[21:23], st.seq)
		out[23] = 0
	}
	copy(out[hdrLen:], tag)
	return out
}

type probeKit struct {
	key    []byte
	shapes []probeShape
}

func newProbeKit() *probeKit {
	k := &probeKit{key: probeRandom(wrapKeyLen)}
	prodCfg := NewObfsConfig()
	prodState := NewObfsState()
	s111 := newProbeRTPState()
	s111e := newProbeRTPState()
	s96 := newProbeRTPState()
	k.shapes = []probeShape{
		{"plain", func(n int, tag []byte) []byte {
			b := probeRandom(max(n, len(tag)))
			copy(b, tag)
			return b
		}},
		{"dtls", func(n int, tag []byte) []byte {
			b := probeRandom(max(n, 13+len(tag)))
			b[0], b[1], b[2] = 0x17, 0xFE, 0xFD
			binary.BigEndian.PutUint16(b[11:13], uint16(len(b)-13))
			copy(b[13:], tag)
			return b
		}},
		{"wdtt-current", func(n int, tag []byte) []byte {
			// Ровно то, что шлёт клиент (obfsWrapPacket), метка внутри шифротекста.
			plainLen := n - 12 - 16 - prodCfg.PaddingMax/2
			if plainLen < len(tag) {
				plainLen = len(tag)
			}
			plain := probeRandom(plainLen)
			copy(plain, tag)
			out, err := obfsWrapPacket(k.key, plain, prodCfg, prodState)
			if err != nil {
				return plain
			}
			return out
		}},
		{"rtp111", func(n int, tag []byte) []byte { return buildProbeRTP(n, tag, s111, 111, false) }},
		{"rtp111-ext", func(n int, tag []byte) []byte { return buildProbeRTP(n, tag, s111e, 111, true) }},
		{"rtp96", func(n int, tag []byte) []byte { return buildProbeRTP(n, tag, s96, 96, false) }},
	}
	return k
}

func probeMakeTag(cell, idx uint16) []byte {
	t := make([]byte, probeTagLen)
	copy(t[0:4], probeMagic[:])
	binary.BigEndian.PutUint16(t[4:6], cell)
	binary.BigEndian.PutUint16(t[6:8], idx)
	binary.BigEndian.PutUint64(t[8:16], uint64(time.Now().UnixNano()))
	return t
}

// probeParseTag ищет метку на известных смещениях, иначе пробует расшифровать obfs.
func (k *probeKit) parseTag(pkt []byte, plainBuf []byte) (cell, idx uint16, sent time.Time, ok bool) {
	check := func(b []byte) bool {
		if len(b) < probeTagLen || [4]byte(b[0:4]) != probeMagic {
			return false
		}
		cell = binary.BigEndian.Uint16(b[4:6])
		idx = binary.BigEndian.Uint16(b[6:8])
		sent = time.Unix(0, int64(binary.BigEndian.Uint64(b[8:16])))
		return true
	}
	for _, off := range []int{0, 12, 13, 24} {
		if len(pkt) >= off+probeTagLen && check(pkt[off:]) {
			return cell, idx, sent, true
		}
	}
	if n, err := obfsUnwrapPacket(k.key, pkt, plainBuf); err == nil && check(plainBuf[:n]) {
		return cell, idx, sent, true
	}
	return 0, 0, time.Time{}, false
}

type probeCellStat struct {
	sent int
	recv map[uint16]struct{}
	lat  []time.Duration
}

type probeCollector struct {
	mu      sync.Mutex
	cells   map[uint16]*probeCellStat
	unknown int
	dup     int
}

func newProbeCollector() *probeCollector {
	return &probeCollector{cells: make(map[uint16]*probeCellStat)}
}

func (c *probeCollector) cell(id uint16) *probeCellStat {
	s, ok := c.cells[id]
	if !ok {
		s = &probeCellStat{recv: make(map[uint16]struct{})}
		c.cells[id] = s
	}
	return s
}

func (c *probeCollector) markSent(id uint16) {
	c.mu.Lock()
	c.cell(id).sent++
	c.mu.Unlock()
}

func (c *probeCollector) got(id, idx uint16, lat time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.cell(id)
	if _, dup := s.recv[idx]; dup {
		c.dup++
		return
	}
	s.recv[idx] = struct{}{}
	s.lat = append(s.lat, lat)
}

func (c *probeCollector) snapshot(id uint16) (sent, recv int, lat []time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.cell(id)
	l := make([]time.Duration, len(s.lat))
	copy(l, s.lat)
	return s.sent, len(s.recv), l
}

func probePct(l []time.Duration, p float64) time.Duration {
	if len(l) == 0 {
		return 0
	}
	s := make([]time.Duration, len(l))
	copy(s, l)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s)-1) * p)
	return s[i]
}

func probeMs(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", d.Milliseconds())
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

// TurnProbeCreds — TURN-креды для пробы (если nil — берутся по хешу).
type TurnProbeCreds struct {
	User, Pass string
	Addrs      []string
}

// TurnProbeOptions — настройки длительности пробы (для тестов).
type TurnProbeOptions struct {
	Quick bool
}

// RunTurnProbe получает TURN-креды по хешу звонка и проверяет, что и с какой
// задержкой VK relay пересылает между двумя аллокациями. Отчёт пишется в out.
func RunTurnProbe(ctx context.Context, hash string, creds *TurnProbeCreds, opts TurnProbeOptions, out io.Writer) error {
	p := func(format string, a ...interface{}) { fmt.Fprintf(out, format+"\n", a...) }

	if creds == nil {
		setupGlobalResolver()
		t0 := time.Now()
		u, pw, addrs, err := GetCreds(ctx, hash, 0)
		if err != nil {
			return fmt.Errorf("получение TURN кредов: %w", err)
		}
		p("креды VK получены за %v", time.Since(t0).Truncate(time.Millisecond))
		creds = &TurnProbeCreds{User: u, Pass: pw, Addrs: addrs}
	}
	if len(creds.Addrs) == 0 {
		return fmt.Errorf("нет TURN адресов")
	}
	p("TURN серверы: %s", strings.Join(creds.Addrs, ", "))

	a, b := creds.Addrs[0], creds.Addrs[0]
	if len(creds.Addrs) > 1 {
		b = creds.Addrs[1]
	}
	p("")
	p("══ A=%s → B=%s ══", a, b)
	return runProbePair(ctx, a, b, creds, opts, p)
}

func runProbePair(ctx context.Context, addrA, addrB string, creds *TurnProbeCreds, opts TurnProbeOptions, p func(string, ...interface{})) error {
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

	// RTT до TURN без relay (STUN Binding) — задержка самого пути до VK.
	var rtts []time.Duration
	for i := 0; i < 5; i++ {
		t0 := time.Now()
		if _, err := tcA.SendBindingRequest(); err == nil {
			rtts = append(rtts, time.Since(t0))
		}
		time.Sleep(100 * time.Millisecond)
	}
	p("RTT до TURN (STUN binding): ответов %d/5, медиана %s мс, макс %s мс", len(rtts), probeMs(probePct(rtts, 0.5)), probeMs(probePct(rtts, 1)))

	kit := newProbeKit()
	col := newProbeCollector()
	var wg sync.WaitGroup
	reader := func(c net.PacketConn) {
		defer wg.Done()
		buf := make([]byte, 2048)
		plain := make([]byte, 2048)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			now := time.Now()
			cell, idx, sent, ok := kit.parseTag(buf[:n], plain)
			if !ok {
				col.mu.Lock()
				col.unknown++
				col.mu.Unlock()
				continue
			}
			col.got(cell, idx, now.Sub(sent))
		}
	}
	wg.Add(2)
	go reader(rb)
	go reader(ra)
	defer func() {
		_ = ra.SetDeadline(time.Now())
		_ = rb.SetDeadline(time.Now())
		wg.Wait()
	}()

	var cellSeq uint16
	newCell := func() uint16 { cellSeq++; return cellSeq }
	send := func(c net.PacketConn, to net.Addr, sh probeShape, size int, cell, idx uint16) {
		pkt := sh.Build(size, probeMakeTag(cell, idx))
		col.markSent(cell)
		_, _ = c.WriteTo(pkt, to)
	}
	sleepCtx := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	rtp := kit.shapes[3]
	prod := kit.shapes[2]

	// Разрешения в обе стороны: первая запись создаёт CreatePermission (+ ChannelBind).
	warm := newCell()
	send(rb, ra.LocalAddr(), rtp, 100, warm, 0)
	send(ra, rb.LocalAddr(), rtp, 100, warm, 1)
	sleepCtx(1500 * time.Millisecond)

	// 1) Пинг маленькими пакетами в обе стороны, 5 пакетов/с.
	pingN := 20
	if opts.Quick {
		pingN = 5
	}
	ab, ba := newCell(), newCell()
	for i := 0; i < pingN; i++ {
		send(ra, rb.LocalAddr(), prod, 120, ab, uint16(i))
		send(rb, ra.LocalAddr(), prod, 120, ba, uint16(i))
		if !sleepCtx(200 * time.Millisecond) {
			return ctx.Err()
		}
	}
	sleepCtx(3 * time.Second)
	for _, x := range []struct {
		name string
		id   uint16
	}{{"A→B", ab}, {"B→A", ba}} {
		s, r, l := col.snapshot(x.id)
		p("пинг %s 120B: дошло %d/%d, задержка p50 %s мс, p95 %s мс, макс %s мс", x.name, r, s,
			probeMs(probePct(l, 0.5)), probeMs(probePct(l, 0.95)), probeMs(probePct(l, 1)))
	}

	// 2) Матрица форма × размер, по 5 пакетов, медленно (10 пакетов/с).
	sizes := []int{100, 300, 600, 1000, 1200, 1400}
	matrix := make(map[string]map[int]uint16)
	for _, sh := range kit.shapes {
		matrix[sh.Name] = make(map[int]uint16)
		for _, sz := range sizes {
			id := newCell()
			matrix[sh.Name][sz] = id
			for i := 0; i < 5; i++ {
				send(ra, rb.LocalAddr(), sh, sz, id, uint16(i))
				if !sleepCtx(100 * time.Millisecond) {
					return ctx.Err()
				}
			}
		}
	}
	sleepCtx(5 * time.Second)
	p("")
	p("Дошло из 5 / медианная задержка (мс):")
	header := fmt.Sprintf("%-13s", "форма\\размер")
	for _, sz := range sizes {
		header += fmt.Sprintf("%11d", sz)
	}
	p("%s", header)
	for _, sh := range kit.shapes {
		line := fmt.Sprintf("%-13s", sh.Name)
		for _, sz := range sizes {
			_, r, l := col.snapshot(matrix[sh.Name][sz])
			line += fmt.Sprintf("%11s", fmt.Sprintf("%d/%s", r, probeMs(probePct(l, 0.5))))
		}
		p("%s", line)
	}

	// 3) Лесенка скоростей: текущий формат клиента, 1200 байт.
	p("")
	p("Лесенка скоростей (wdtt-current, 1200B):")
	rates := []float64{0.25, 0.5, 1, 2, 4, 8, 16}
	stepDur := 4 * time.Second
	if opts.Quick {
		rates = []float64{1, 8}
		stepDur = time.Second
	}
	for _, mbps := range rates {
		id := newCell()
		const size = 1200
		pps := mbps * 1e6 / 8 / size
		interval := time.Duration(float64(time.Second) / pps)
		start := time.Now()
		next := start
		var idx uint16
		for time.Since(start) < stepDur {
			send(ra, rb.LocalAddr(), prod, size, id, idx)
			idx++
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				if !sleepCtx(d) {
					return ctx.Err()
				}
			}
		}
		// Ждём хвост: пока пакеты продолжают приходить (до 10 с).
		deadline := time.Now().Add(10 * time.Second)
		last := -1
		for time.Now().Before(deadline) {
			if !sleepCtx(time.Second) {
				return ctx.Err()
			}
			_, r, _ := col.snapshot(id)
			if r == last {
				break
			}
			last = r
		}
		s, r, l := col.snapshot(id)
		loss := 0.0
		if s > 0 {
			loss = 100 * float64(s-r) / float64(s)
		}
		p("  %5.2f Мбит/с: дошло %d/%d (потери %.0f%%), задержка p50 %s мс, p95 %s мс, макс %s мс",
			mbps, r, s, loss, probeMs(probePct(l, 0.5)), probeMs(probePct(l, 0.95)), probeMs(probePct(l, 1)))
		if s > 0 && loss > 60 && probePct(l, 0.5) > 2*time.Second {
			p("  (дальше не повышаю — канал уже забит)")
			break
		}
	}

	col.mu.Lock()
	p("")
	p("непомеченных пакетов: %d, дублей: %d", col.unknown, col.dup)
	col.mu.Unlock()
	return nil
}
