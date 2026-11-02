# allowedips

A self-contained WireGuard `AllowedIPs` calculator, modelled on the
[Pro Custodibus calculator](https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/).
It subtracts "disallowed" IP blocks from "allowed" IP blocks and prints the
smallest list of CIDR blocks for a peer's `AllowedIPs` setting. IPv4 and IPv6
are both supported and handled independently.

Written in Go using only the standard library (no third-party modules, no
frameworks). It builds to a single static binary; the web page is embedded in it.

C# was the first choice, but the build environment had no .NET SDK and could not
install one, so the code could not have been compiled or tested. Go was the next
choice offered.

## Build

    go build -o allowedips .                              # needs Go 1.21+
    GOOS=windows GOARCH=amd64 go build -o allowedips.exe .   # cross-compile
    GOOS=darwin  GOARCH=arm64 go build -o allowedips .

## CLI (default)

    allowedips -a 0.0.0.0/0 ::/0 -d 10.0.0.0/8 192.168.0.0/16 fc00::/7
    allowedips -a 0.0.0.0/0,::/0 -d 10.0.0.0/8,192.168.0.0/16,fc00::/7
    allowedips --allowed 10.0.0.0/8 --disallowed 10.0.1.0/24 --format lines

`-a`/`--allowed` and `-d`/`--disallowed` take any number of values, space- and/or
comma-separated, and may be repeated. A bare address means a single host. Host
bits are cleared (`10.0.0.5/8` becomes `10.0.0.0/8`).

`-f`/`--format`: `wg` (default, `AllowedIPs = a, b, c`), `list` (`a, b, c`), or
`lines` (one block per line).

**Quoting:** none needed. IPv4/IPv6 notation only uses hex digits, `.`, `:` and
`/`, none of which bash, zsh, sh, cmd.exe or PowerShell treat specially. Commas
are fine too (PowerShell and cmd.exe may turn them into separate arguments,
which the parser accepts). Quotes are only needed if you put *spaces inside a
single argument*, e.g. `-a "10.0.0.0/8, 192.168.0.0/16"`; that works as well.

Exit codes: 0 success, 1 invalid input or runtime error, 2 usage error.

## Server

    allowedips --server 127.0.0.1:8080
    allowedips --server [::1]:8080
    allowedips --server :8080           # all interfaces

Then open the printed URL. The page has the same two fields as the original
calculator, plus a Copy button. It works without JavaScript apart from the Copy
button. There is no authentication; bind to a loopback address unless you
really want it reachable from the network (a warning is printed if you don't).
Stop with Ctrl+C.

## Behaviour notes

* The output is the *minimal* CIDR list covering exactly (allowed − disallowed),
  IPv4 first, then IPv6, each sorted by address. Overlapping and adjacent
  allowed blocks are merged. Results are identical to the published examples.
* Input may also contain WireGuard-style lines (`AllowedIPs = a, b`), `#`
  comments, and `;`/newline separators.
* IPv4-mapped IPv6 blocks (`::ffff:0:0/96`) are treated as IPv6, as WireGuard does.
* Zone identifiers (`fe80::1%eth0`) are rejected.

## Tests

    go test ./...

Covers the published examples verbatim, edge cases, parsing, and a randomized
brute-force comparison (every address in a /16 or /112 window) that also checks
the output is sorted, disjoint and minimal.
