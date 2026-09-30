package core

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/pion/turn/v5"
)

// Прогоняет пробу против локального pion TURN, который пропускает всё.
func TestRunTurnProbeLocal(t *testing.T) {
	if testing.Short() {
		t.Skip("долгий тест")
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "test",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, ra.Realm, "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		LoggerFactory: &NullLoggerFactory{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var out bytes.Buffer
	err = RunTurnProbe(context.Background(), "", &TurnProbeCreds{User: "u", Pass: "pass", Addrs: []string{pc.LocalAddr().String()}}, &out)
	t.Log("\n" + out.String())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ОШИБКА") || !strings.Contains(out.String(), "wdtt-current     5/5") {
		t.Fatal("проба не прошла на локальном TURN")
	}
}
