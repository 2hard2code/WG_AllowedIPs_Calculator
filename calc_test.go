package main

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

func mustCalc(t *testing.T, allowed, disallowed string) Result {
	t.Helper()
	a, err := ParseList(allowed)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseList(disallowed)
	if err != nil {
		t.Fatal(err)
	}
	return Calculate(a, d)
}

// Expected values are the outputs published on
// https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/
func TestBlogExamples(t *testing.T) {
	cases := []struct{ allowed, disallowed, want string }{
		{
			"10.0.0.0/8", "10.0.1.0/24",
			"10.0.0.0/24, 10.0.2.0/23, 10.0.4.0/22, 10.0.8.0/21, 10.0.16.0/20, 10.0.32.0/19, 10.0.64.0/18, 10.0.128.0/17, 10.1.0.0/16, 10.2.0.0/15, 10.4.0.0/14, 10.8.0.0/13, 10.16.0.0/12, 10.32.0.0/11, 10.64.0.0/10, 10.128.0.0/9",
		},
		{
			"0.0.0.0/0", "10.0.0.0/8",
			"0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1",
		},
		{
			"0.0.0.0/0, ::/0",
			"0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 240.0.0.0/4, fc00::/7, fe80::/10",
			"1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/3, 96.0.0.0/4, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/8, 169.0.0.0/9, 169.128.0.0/10, 169.192.0.0/11, 169.224.0.0/12, 169.240.0.0/13, 169.248.0.0/14, 169.252.0.0/15, 169.255.0.0/16, 170.0.0.0/7, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 224.0.0.0/4, ::/1, 8000::/2, c000::/3, e000::/4, f000::/5, f800::/6, fe00::/9, fec0::/10, ff00::/8",
		},
	}
	for _, c := range cases {
		if got := mustCalc(t, c.allowed, c.disallowed).String(); got != c.want {
			t.Errorf("allowed=%q disallowed=%q\n got: %s\nwant: %s", c.allowed, c.disallowed, got, c.want)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	cases := []struct{ name, allowed, disallowed, want string }{
		{"no disallowed keeps block", "10.0.0.0/8", "", "10.0.0.0/8"},
		{"everything disallowed", "10.0.0.0/8", "0.0.0.0/0", ""},
		{"disallowed equals allowed", "192.168.1.0/24", "192.168.1.0/24", ""},
		{"disallowed elsewhere", "10.0.0.0/8", "11.0.0.0/8", "10.0.0.0/8"},
		{"overlapping allowed merge", "10.0.0.0/9, 10.128.0.0/9, 10.5.0.0/16", "", "10.0.0.0/8"},
		{"adjacent allowed merge", "10.0.0.0/25, 10.0.0.128/25", "", "10.0.0.0/24"},
		{"host bits are cleared", "10.1.2.3/8", "", "10.0.0.0/8"},
		{"bare addresses", "10.0.0.1, 10.0.0.2", "", "10.0.0.1/32, 10.0.0.2/32"},
		{"host removed from /31", "10.0.0.0/31", "10.0.0.1", "10.0.0.0/32"},
	}
	for _, c := range cases {
		if got := mustCalc(t, c.allowed, c.disallowed).String(); got != c.want {
			t.Errorf("%s:\n got: %q\nwant: %q", c.name, got, c.want)
		}
	}
}

func TestV6FullMinusOneHost(t *testing.T) {
	r := mustCalc(t, "::/0", "::1")
	if len(r.V4) != 0 || len(r.V6) != 128 {
		t.Fatalf("got %d v4 / %d v6 blocks, want 0 / 128", len(r.V4), len(r.V6))
	}
	if r.V6[0].String() != "::/128" || r.V6[1].String() != "::2/127" || r.V6[127].String() != "8000::/1" {
		t.Errorf("unexpected blocks: %v %v ... %v", r.V6[0], r.V6[1], r.V6[127])
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{
		"10.0.0.0/33", "300.1.1.1", "fe80::1%eth0", "10.0.0.0/8/9", "hello", "::/129",
		"PostUp = 10.0.0.0/8",
	} {
		if _, err := ParseList(s); err == nil {
			t.Errorf("ParseList(%q): expected an error", s)
		}
	}
}

func TestParseFormats(t *testing.T) {
	got, err := ParseList("# comment\nAllowedIPs = 10.0.0.0/8, ::/0\nallowedips=192.168.0.1;172.16.0.0/12\n\n  fc00::/7\t1.1.1.1\r\n")
	if err != nil {
		t.Fatal(err)
	}
	want := "10.0.0.0/8 ::/0 192.168.0.1/32 172.16.0.0/12 fc00::/7 1.1.1.1/32"
	var parts []string
	for _, p := range got {
		parts = append(parts, p.String())
	}
	if strings.Join(parts, " ") != want {
		t.Errorf("got %v want %s", parts, want)
	}
}

// Brute force: compare against explicit address-by-address set arithmetic in a
// small space, and check that the output is canonical (sorted, disjoint, and
// no two blocks that could be merged into one).
func TestBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 300; iter++ {
		// 16-bit window: v4 10.1.0.0/16, and v6 2001:db8::/112.
		for _, fam := range []string{"v4", "v6"} {
			base, width := netip.MustParseAddr("10.1.0.0"), 32
			if fam == "v6" {
				base, width = netip.MustParseAddr("2001:db8::"), 128
			}
			randPrefix := func() netip.Prefix {
				plen := width - 16 + rng.Intn(17) // /16.. /32 (or /112../128)
				b := base.AsSlice()
				v := rng.Intn(1 << 16)
				b[len(b)-2] = byte(v >> 8)
				b[len(b)-1] = byte(v)
				a, _ := netip.AddrFromSlice(b)
				return netip.PrefixFrom(a, plen).Masked()
			}
			var allowed, disallowed []netip.Prefix
			for i, n := 0, 1+rng.Intn(4); i < n; i++ {
				allowed = append(allowed, randPrefix())
			}
			for i, n := 0, rng.Intn(6); i < n; i++ {
				disallowed = append(disallowed, randPrefix())
			}
			res := Calculate(allowed, disallowed).All()

			inAny := func(a netip.Addr, ps []netip.Prefix) bool {
				for _, p := range ps {
					if p.Contains(a) {
						return true
					}
				}
				return false
			}
			b := base.AsSlice()
			for v := 0; v < 1<<16; v++ {
				bb := append([]byte(nil), b...)
				bb[len(bb)-2], bb[len(bb)-1] = byte(v>>8), byte(v)
				a, _ := netip.AddrFromSlice(bb)
				want := inAny(a, allowed) && !inAny(a, disallowed)
				if got := inAny(a, res); got != want {
					t.Fatalf("%s iter %d: addr %s got=%v want=%v\nallowed=%v\ndisallowed=%v\nresult=%v", fam, iter, a, got, want, allowed, disallowed, res)
				}
			}
			// Canonical form checks.
			for i := 1; i < len(res); i++ {
				p, q := res[i-1], res[i]
				if p.Overlaps(q) || p.Addr().Compare(q.Addr()) >= 0 {
					t.Fatalf("output not sorted/disjoint: %v then %v", p, q)
				}
				// Mergeable siblings: same length, p aligned to parent, q == p's sibling.
				if p.Bits() == q.Bits() && p.Bits() > 0 {
					parent, _ := p.Addr().Prefix(p.Bits() - 1)
					if parent.Contains(q.Addr()) {
						t.Fatalf("output not minimal: %v and %v can merge", p, q)
					}
				}
			}
		}
	}
}
