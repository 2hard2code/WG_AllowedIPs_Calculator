// allowedips: a self-contained WireGuard AllowedIPs calculator.
//
// It subtracts "disallowed" IP blocks from "allowed" IP blocks and prints the
// smallest list of CIDR blocks for the WireGuard AllowedIPs setting. It runs
// as a command-line tool by default, or as a local web server with --server.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `allowedips - WireGuard AllowedIPs calculator (IPv4 and IPv6)

Subtracts "disallowed" blocks from "allowed" blocks and prints the minimal
list of CIDR blocks to put in a WireGuard peer's AllowedIPs setting.

Usage:
  allowedips -a ALLOWED... [-d DISALLOWED...] [-f FORMAT]
  allowedips --server IP:PORT

Options:
  -a, --allowed ADDR...     Allowed blocks. Accepts several values, each a
                            CIDR block or a single address; values may be
                            space- or comma-separated.
  -d, --disallowed ADDR...  Blocks to subtract from the allowed ones.
  -f, --format FORMAT       Output format (default: wg):
                              wg     AllowedIPs = a, b, c
                              list   a, b, c
                              lines  one block per line
  -s, --server IP:PORT      Run as a web server instead, e.g. 127.0.0.1:8080
                            or [::1]:8080 (':8080' listens on all interfaces).
  -h, --help                Show this help.

No quoting is needed: IPv4/IPv6 notation contains no characters that bash,
zsh, sh or PowerShell treat specially (only ':', '.', '/' and hex digits).

Examples:
  allowedips -a 0.0.0.0/0 ::/0 -d 10.0.0.0/8 192.168.0.0/16 fc00::/7
  allowedips -a 0.0.0.0/0,::/0 -d 10.0.0.0/8,192.168.0.0/16,fc00::/7
  allowedips --allowed 10.0.0.0/8 --disallowed 10.0.1.0/24 --format lines
  allowedips --server 127.0.0.1:8080
`

type options struct {
	allowed    []string
	disallowed []string
	format     string
	server     string
	help       bool
}

func parseArgs(args []string) (options, error) {
	opts := options{format: "wg"}
	var collect *[]string // list currently receiving positional values
	needValue := func(name string, i *int, inline string, hasInline bool) (string, error) {
		if hasInline {
			return inline, nil
		}
		if *i+1 >= len(args) || strings.HasPrefix(args[*i+1], "-") {
			return "", fmt.Errorf("option %s needs a value", name)
		}
		*i++
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if collect == nil {
				return opts, fmt.Errorf("unexpected argument %q (put addresses after -a or -d)", arg)
			}
			*collect = append(*collect, arg)
			continue
		}

		name, inline, hasInline := arg, "", false
		if strings.HasPrefix(arg, "--") {
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				name, inline, hasInline = arg[:eq], arg[eq+1:], true
			}
		}

		switch name {
		case "-a", "--allowed":
			collect = &opts.allowed
			if hasInline {
				opts.allowed = append(opts.allowed, inline)
			}
		case "-d", "--disallowed":
			collect = &opts.disallowed
			if hasInline {
				opts.disallowed = append(opts.disallowed, inline)
			}
		case "-f", "--format":
			collect = nil
			v, err := needValue(name, &i, inline, hasInline)
			if err != nil {
				return opts, err
			}
			opts.format = strings.ToLower(v)
		case "-s", "--server":
			collect = nil
			v, err := needValue(name, &i, inline, hasInline)
			if err != nil {
				return opts, err
			}
			opts.server = v
		case "-h", "--help":
			opts.help = true
		default:
			return opts, fmt.Errorf("unknown option %q", arg)
		}
	}
	return opts, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "allowedips: %v\n\n%s", err, usage)
		return 2
	}
	if opts.help {
		fmt.Fprint(stdout, usage)
		return 0
	}

	if opts.server != "" {
		if len(opts.allowed) > 0 || len(opts.disallowed) > 0 {
			fmt.Fprintln(stderr, "allowedips: --server cannot be combined with -a/-d")
			return 2
		}
		if err := serve(opts.server, stderr); err != nil {
			fmt.Fprintf(stderr, "allowedips: %v\n", err)
			return 1
		}
		return 0
	}

	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if len(opts.allowed) == 0 {
		fmt.Fprintf(stderr, "allowedips: no allowed blocks given (use -a)\n\n%s", usage)
		return 2
	}
	switch opts.format {
	case "wg", "list", "lines":
	default:
		fmt.Fprintf(stderr, "allowedips: unknown format %q (use wg, list or lines)\n", opts.format)
		return 2
	}

	allowed, err := ParseList(strings.Join(opts.allowed, "\n"))
	if err != nil {
		fmt.Fprintf(stderr, "allowedips: allowed: %v\n", err)
		return 1
	}
	disallowed, err := ParseList(strings.Join(opts.disallowed, "\n"))
	if err != nil {
		fmt.Fprintf(stderr, "allowedips: disallowed: %v\n", err)
		return 1
	}

	res := Calculate(allowed, disallowed)
	if len(res.All()) == 0 {
		fmt.Fprintln(stderr, "allowedips: nothing is left after subtraction; the result is empty")
	}
	switch opts.format {
	case "wg":
		fmt.Fprintln(stdout, strings.TrimRight("AllowedIPs = "+res.String(), " "))
	case "list":
		fmt.Fprintln(stdout, res.String())
	case "lines":
		for _, p := range res.All() {
			fmt.Fprintln(stdout, p)
		}
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
