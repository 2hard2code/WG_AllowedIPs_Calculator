package main

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// ParseList parses a list of IPv4/IPv6 addresses and CIDR blocks.
//
// Entries may be separated by commas, semicolons, spaces, tabs or newlines.
// A bare address is treated as a single-host block (/32 or /128). Host bits
// are cleared (10.0.0.5/8 becomes 10.0.0.0/8). For convenience, lines of the
// form "AllowedIPs = a, b" (as found in a WireGuard config) are accepted too,
// and lines starting with '#' are ignored.
func ParseList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			key := strings.ToLower(strings.TrimSpace(line[:i]))
			if key != "allowedips" && key != "disallowedips" {
				return nil, fmt.Errorf("unexpected text %q (expected a list of IP addresses or CIDR blocks)", strings.TrimSpace(line[:i]))
			}
			line = line[i+1:]
		}
		tokens := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r'
		})
		for _, tok := range tokens {
			p, err := parseToken(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func parseToken(tok string) (netip.Prefix, error) {
	if strings.Contains(tok, "/") {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address block %q", tok)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(tok)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", tok)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ---------------------------------------------------------------------------
// Calculation
// ---------------------------------------------------------------------------

// Result holds the minimal CIDR lists of one calculation, per address family,
// each sorted by address.
type Result struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// All returns IPv4 blocks followed by IPv6 blocks.
func (r Result) All() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.V4)+len(r.V6))
	out = append(out, r.V4...)
	return append(out, r.V6...)
}

// String renders the blocks as "a, b, c" (empty string if there are none).
func (r Result) String() string {
	all := r.All()
	parts := make([]string, len(all))
	for i, p := range all {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

// Calculate subtracts the disallowed blocks from the allowed blocks and
// returns the smallest list of CIDR blocks covering exactly what remains.
// IPv4 and IPv6 are handled independently (an IPv4-mapped IPv6 block such as
// ::ffff:0:0/96 is an IPv6 block, as it is for WireGuard).
func Calculate(allowed, disallowed []netip.Prefix) Result {
	a4, a6 := split(allowed)
	d4, d6 := split(disallowed)
	return Result{
		V4: subtract(a4, d4, 32),
		V6: subtract(a6, d6, 128),
	}
}

func split(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

// interval is an inclusive range of addresses, as integers.
type interval struct{ lo, hi *big.Int }

var one = big.NewInt(1)

func toInterval(p netip.Prefix) interval {
	a := p.Addr()
	lo := new(big.Int).SetBytes(a.AsSlice())
	size := new(big.Int).Lsh(one, uint(a.BitLen()-p.Bits()))
	hi := new(big.Int).Add(lo, size)
	hi.Sub(hi, one)
	return interval{lo, hi}
}

// normalize sorts intervals and merges overlapping or adjacent ones.
func normalize(ivs []interval) []interval {
	if len(ivs) == 0 {
		return nil
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo.Cmp(ivs[j].lo) < 0 })
	out := []interval{{new(big.Int).Set(ivs[0].lo), new(big.Int).Set(ivs[0].hi)}}
	for _, iv := range ivs[1:] {
		last := &out[len(out)-1]
		next := new(big.Int).Add(last.hi, one)
		if iv.lo.Cmp(next) <= 0 {
			if iv.hi.Cmp(last.hi) > 0 {
				last.hi = new(big.Int).Set(iv.hi)
			}
			continue
		}
		out = append(out, interval{new(big.Int).Set(iv.lo), new(big.Int).Set(iv.hi)})
	}
	return out
}

func subtract(allowed, disallowed []netip.Prefix, bits int) []netip.Prefix {
	if len(allowed) == 0 {
		return nil
	}
	var ai, di []interval
	for _, p := range allowed {
		ai = append(ai, toInterval(p))
	}
	for _, p := range disallowed {
		di = append(di, toInterval(p))
	}
	a, d := normalize(ai), normalize(di)

	var rest []interval
	j := 0
	for _, x := range a {
		cur := new(big.Int).Set(x.lo)
		for j < len(d) && d[j].hi.Cmp(cur) < 0 {
			j++
		}
		k := j
		for k < len(d) && d[k].lo.Cmp(x.hi) <= 0 {
			if d[k].lo.Cmp(cur) > 0 {
				rest = append(rest, interval{new(big.Int).Set(cur), new(big.Int).Sub(d[k].lo, one)})
			}
			if next := new(big.Int).Add(d[k].hi, one); next.Cmp(cur) > 0 {
				cur = next
			}
			k++
		}
		if cur.Cmp(x.hi) <= 0 {
			rest = append(rest, interval{cur, new(big.Int).Set(x.hi)})
		}
		// The last overlapping disallowed block may extend into the next
		// allowed interval, so do not skip past it.
		if k-1 > j {
			j = k - 1
		}
	}

	var out []netip.Prefix
	for _, iv := range rest {
		out = append(out, intervalToPrefixes(iv, bits)...)
	}
	return out
}

// intervalToPrefixes converts an inclusive address range to the minimal list
// of CIDR blocks that exactly covers it.
func intervalToPrefixes(iv interval, bits int) []netip.Prefix {
	var out []netip.Prefix
	lo := new(big.Int).Set(iv.lo)
	buf := make([]byte, bits/8)
	for {
		// Largest block size 2^k such that lo is aligned to it...
		k := bits
		if lo.Sign() != 0 {
			k = int(lo.TrailingZeroBits())
		}
		// ...and it still fits in the remaining range: 2^k <= hi-lo+1.
		remaining := new(big.Int).Sub(iv.hi, lo)
		remaining.Add(remaining, one)
		if fit := remaining.BitLen() - 1; k > fit {
			k = fit
		}

		addr, _ := netip.AddrFromSlice(lo.FillBytes(buf))
		out = append(out, netip.PrefixFrom(addr, bits-k))

		end := new(big.Int).Lsh(one, uint(k))
		end.Add(end, lo)
		end.Sub(end, one)
		if end.Cmp(iv.hi) >= 0 {
			return out
		}
		lo = end.Add(end, one)
	}
}
