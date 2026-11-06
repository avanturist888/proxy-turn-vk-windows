//go:build windows

package control

import (
	"fmt"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	t.Setenv("WDTT_PIPE", fmt.Sprintf(`\\.\pipe\wdtt-control-test-%d`, time.Now().UnixNano()))
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Serve(l, func(r Request) Response {
		if r.Cmd == "boom" {
			panic("boom")
		}
		return Response{OK: true, Message: r.Cmd + ":" + r.Profile, Status: &Status{State: StateConnected, Workers: 9}}
	})

	resp, err := Call(Request{Cmd: CmdSwitch, Profile: "s1"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Message != "switch:s1" || resp.Status.Workers != 9 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	resp, err = Call(Request{Cmd: "boom"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error == "" {
		t.Fatalf("panic must turn into an error response: %+v", resp)
	}
}

func TestCallWithoutServer(t *testing.T) {
	t.Setenv("WDTT_PIPE", `\\.\pipe\wdtt-control-nobody-listens`)
	if _, err := Call(Request{Cmd: CmdStatus}, time.Second); err == nil {
		t.Fatal("expected an error when nothing listens")
	}
}
