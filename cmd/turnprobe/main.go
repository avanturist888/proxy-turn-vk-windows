// turnprobe — диагностика VK TURN: какие пакеты relay пересылает.
//
// Использование:
//   turnprobe.exe -vk HASH
//
// Поднимает две аллокации на TURN VK и гоняет между ними пакеты разной
// формы/размера. VPS не нужен. Вывод можно скопировать целиком.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"wg-turn-client/core"
)

func main() {
	vkHash := flag.String("vk", "", "хеш VK-звонка")
	fingerprint := flag.String("fingerprint", "chrome", "браузерный фингерпринт")
	flag.Parse()

	hashes := core.ParseHashes(*vkHash)
	if len(hashes) == 0 {
		fmt.Println("Использование: turnprobe.exe -vk HASH")
		waitEnter()
		os.Exit(2)
	}
	core.SetActiveFingerprint(*fingerprint)

	f, _ := os.Create("turnprobe.log")
	var out io.Writer = os.Stdout
	if f != nil {
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	}
	log.SetOutput(out)
	log.SetFlags(log.Ltime)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; cancel() }()

	fmt.Fprintf(out, "turnprobe %s\n", time.Now().Format(time.RFC3339))
	if err := core.RunTurnProbe(ctx, hashes[0], nil, core.TurnProbeOptions{}, out); err != nil {
		fmt.Fprintf(out, "ОШИБКА: %v\n", err)
	}
	fmt.Fprintln(out, "\nГотово. Результат сохранён в turnprobe.log")
	waitEnter()
}

func waitEnter() {
	fmt.Println("Нажмите Enter для выхода...")
	_, _ = fmt.Scanln()
}
