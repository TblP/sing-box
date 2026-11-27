package masque

import (
	"strconv"
	"testing"
)

func TestConnectUDPURLEscapesTargetOnce(t *testing.T) {
	cases := []struct {
		host    string
		port    int
		escaped string
	}{
		{"1.2.3.4", 53, "/.well-known/masque/udp/1.2.3.4/53/"},
		{"prtg.tblp.ru", 443, "/.well-known/masque/udp/prtg.tblp.ru/443/"},
		{
			"2001:db8::42", 443,
			"/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
		},
	}
	for _, tc := range cases {
		u := connectUDPURL("proxy.example:443", tc.host, tc.port)
		if got := u.EscapedPath(); got != tc.escaped {
			t.Errorf("host %q: EscapedPath() = %q, want %q", tc.host, got, tc.escaped)
		}
		if u.Path != masquePathPrefix+tc.host+"/"+strconv.Itoa(tc.port)+"/" {
			t.Errorf("host %q: Path = %q", tc.host, u.Path)
		}
	}
}
