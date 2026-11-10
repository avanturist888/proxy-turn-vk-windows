package core

import (
	"sync/atomic"
	"time"
)

// wgKeepaliveLen — длина пустого транспортного сообщения WireGuard
// (persistent keepalive): заголовок 16 байт + тег Poly1305 16 байт.
const wgKeepaliveLen = 32

// wgOneWayMaxLen — транспортные сообщения WireGuard не длиннее этого могут
// быть пакетами, на которые ответа не бывает: чистый TCP ACK (IPv4/IPv6, с
// метками времени и SACK), ACK-only QUIC. Внутренний пакет до 80 байт после
// выравнивания до 16 + 32 байта заголовка и тега дают не больше 112.
// На простое такой «последний ACK» уходил через воркер, и воркер через
// sessionDeadAfter считался мёртвым — сотни лишних TURN-аллокаций в час.
const wgOneWayMaxLen = 112

// minUnanswered — сколько пакетов, ждущих ответа, должно уйти без ответа,
// чтобы сессию признать мёртвой. Мёртвый воркер под нагрузкой набирает их
// за доли секунды; одиночный пакет без ответа на простое — не повод.
const minUnanswered = 3

// expectsReply — ждать ли на этот пакет хоть какого-то ответа от сервера.
// Keepalive и короткие транспортные пакеты (см. wgOneWayMaxLen) не в счёт:
// ответа на них может не быть вовсе. Рукопожатие и данные — в счёт.
func expectsReply(pkt []byte) bool {
	if len(pkt) > 0 && pkt[0] == 4 && len(pkt) <= wgOneWayMaxLen {
		return false
	}
	return true
}

// liveness решает, мертва ли сессия.
//
// Тишина сама по себе — не признак смерти: сервер может не отвечать на наш
// DTLS-keepalive (так у серверов без pong), а WireGuard на сервере отвечает
// туда, откуда пришёл последний пакет, — простаивающий воркер законно ничего
// не получает. Раньше такой воркер через sessionDeadAfter закрывался, на
// простое это давало сотни новых TURN-аллокаций в час.
//
// Мёртвой сессия считается, только если через неё ушли пакеты, ждущие ответа
// (не меньше minUnanswered), а с первого из них за sessionDeadAfter не пришло
// ничего. Диспетчер шлёт подряд
// идущие пакеты через один воркер (chunk affinity), поэтому ответ на редкий
// пакет приходит через этот же воркер.
type liveness struct {
	lastRx        atomic.Int64 // unix-nano последнего принятого пакета
	awaitingSince atomic.Int64 // unix-nano первого пакета без ответа, 0 — таких нет
	unanswered    atomic.Int32 // сколько пакетов, ждущих ответа, ушло после последнего приёма
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
		l.unanswered.Add(1)
	}
}

// received — от сервера пришёл пакет (данные или pong).
func (l *liveness) received(now time.Time) {
	l.lastRx.Store(now.UnixNano())
	l.awaitingSince.Store(0)
	l.unanswered.Store(0)
}

// dead — сессия мертва; silent — сколько длится тишина.
func (l *liveness) dead(now time.Time, after time.Duration) (bool, time.Duration) {
	silent := now.Sub(time.Unix(0, l.lastRx.Load()))
	since := l.awaitingSince.Load()
	if since == 0 || l.unanswered.Load() < minUnanswered {
		return false, silent
	}
	return now.Sub(time.Unix(0, since)) > after, silent
}
