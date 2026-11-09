package core

import (
	"sync/atomic"
	"time"
)

// wgKeepaliveLen — длина пустого транспортного сообщения WireGuard
// (persistent keepalive): заголовок 16 байт + тег Poly1305 16 байт.
const wgKeepaliveLen = 32

// expectsReply — ждать ли на этот пакет хоть какого-то ответа от сервера.
// На keepalive WireGuard ответа не бывает, и считать его «вопросом без
// ответа» нельзя: на простое сессия выглядела бы мёртвой.
func expectsReply(pkt []byte) bool {
	return !(len(pkt) == wgKeepaliveLen && pkt[0] == 4)
}

// liveness решает, мертва ли сессия.
//
// Тишина сама по себе — не признак смерти: сервер может не отвечать на наш
// DTLS-keepalive (так у серверов без pong), а WireGuard на сервере отвечает
// туда, откуда пришёл последний пакет, — простаивающий воркер законно ничего
// не получает. Раньше такой воркер через sessionDeadAfter закрывался, на
// простое это давало сотни новых TURN-аллокаций в час.
//
// Мёртвой сессия считается, только если через неё ушёл пакет, ждущий ответа,
// а после этого за sessionDeadAfter не пришло ничего. Диспетчер шлёт подряд
// идущие пакеты через один воркер (chunk affinity), поэтому ответ на редкий
// пакет приходит через этот же воркер.
type liveness struct {
	lastRx        atomic.Int64 // unix-nano последнего принятого пакета
	awaitingSince atomic.Int64 // unix-nano первого пакета без ответа, 0 — таких нет
}

func newLiveness(now time.Time) *liveness {
	l := &liveness{}
	l.lastRx.Store(now.UnixNano())
	return l
}

// sent — пакет ушёл к серверу.
func (l *liveness) sent(pkt []byte, now time.Time) {
	if expectsReply(pkt) {
		l.awaitingSince.CompareAndSwap(0, now.UnixNano())
	}
}

// received — от сервера пришёл пакет (данные или pong).
func (l *liveness) received(now time.Time) {
	l.lastRx.Store(now.UnixNano())
	l.awaitingSince.Store(0)
}

// dead — сессия мертва; silent — сколько длится тишина.
func (l *liveness) dead(now time.Time, after time.Duration) (bool, time.Duration) {
	silent := now.Sub(time.Unix(0, l.lastRx.Load()))
	since := l.awaitingSince.Load()
	if since == 0 {
		return false, silent
	}
	return now.Sub(time.Unix(0, since)) > after, silent
}
