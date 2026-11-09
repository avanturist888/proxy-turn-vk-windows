package backend

import "testing"

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"2.1.6.0-dev", "2.1.6.1", true},
		{"2.1.6.1", "2.1.6.1", false},
		{"2.1.6.1", "2.1.6.2", true},
		{"2.1.6.2", "2.1.6.1", false},
		{"2.1.6.3", "2.1.7", true},
		{"2.1.5", "v2.1.6.1", true},
		{"2.1.6.1", "2.1.6", false},
	}
	for _, c := range cases {
		if got := isNewerVersion(c.cur, c.latest); got != c.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}
