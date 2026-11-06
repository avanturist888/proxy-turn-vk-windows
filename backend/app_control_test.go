//go:build windows

package backend

import (
	"testing"

	"wdtt-desktop/control"
)

var testProfiles = []control.ProfileInfo{
	{Name: "alpha", Peer: "192.0.2.1:3478"},
	{Name: "beta", Peer: "192.0.2.2:3478"},
	{Name: "gamma", Peer: "192.0.2.3:56000"},
}

func TestNextProfile(t *testing.T) {
	cases := []struct{ cur, want string }{
		{"alpha", "beta"},
		{"gamma", "alpha"}, // по кругу
		{"", "alpha"},      // текущего нет — первый
		{"gone", "alpha"},  // текущий удалён — первый
	}
	for _, c := range cases {
		if got, ok := nextProfile(testProfiles, c.cur); !ok || got != c.want {
			t.Errorf("nextProfile(%q) = %q, %v; want %q", c.cur, got, ok, c.want)
		}
	}
	if _, ok := nextProfile(testProfiles[:1], "alpha"); ok {
		t.Error("с одним профилем переключаться некуда")
	}
}

func TestFindProfile(t *testing.T) {
	cases := map[string]string{
		"beta":            "beta",
		"BETA":            "beta",
		"192.0.2.3":       "gamma",
		"192.0.2.3:56000": "gamma",
		"192.0.2":         "", // не префикс адреса
		"nosuch":          "",
	}
	for in, want := range cases {
		got, ok := findProfile(testProfiles, in)
		if (want == "") == ok || got != want {
			t.Errorf("findProfile(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestParamsForProfile(t *testing.T) {
	base := ConnectParams{Profile: "sub-1", PeerAddr: "192.0.2.9:3478", Password: "p", Workers: 18, Hashes: []string{"h"}, AutoReconnect: true}
	// Другой профиль: данные подписки сбрасываются, настройки остаются.
	p := paramsForProfile(base, "beta")
	if p.Profile != "beta" || p.PeerAddr != "" || p.Password != "" || p.Workers != 18 || len(p.Hashes) != 1 || !p.AutoReconnect {
		t.Errorf("unexpected params: %+v", p)
	}
	// Тот же профиль подписки — данные подписки сохраняются.
	if p := paramsForProfile(base, "sub-1"); p.PeerAddr != base.PeerAddr {
		t.Errorf("subscription data lost: %+v", p)
	}
}

func TestDecodeMaybeUTF16(t *testing.T) {
	s := `<Command>C:\Program Files\WDTT\wdtt.exe</Command>`
	utf16le := []byte{0xFF, 0xFE}
	for _, r := range s {
		utf16le = append(utf16le, byte(r), 0)
	}
	for name, b := range map[string][]byte{"ascii": []byte(s), "utf16le": utf16le} {
		m := taskCommandRe.FindStringSubmatch(decodeMaybeUTF16(b))
		if m == nil || m[1] != `C:\Program Files\WDTT\wdtt.exe` {
			t.Errorf("%s: got %v", name, m)
		}
	}
}
