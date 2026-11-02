package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed index.html
var indexHTML string

var page = template.Must(template.New("index").Parse(indexHTML))

// maxBody caps request bodies; the calculator is cheap, but not unbounded.
const maxBody = 256 << 10

type pageData struct {
	Nonce      string
	Allowed    string
	Disallowed string
	Submitted  bool
	Error      string
	Line       string
	V4, V6     int
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := pageData{Nonce: base64.StdEncoding.EncodeToString(nonceBytes)}

	status := http.StatusOK
	if r.Form.Has("allowed") || r.Form.Has("disallowed") {
		data.Submitted = true
		data.Allowed = r.Form.Get("allowed")
		data.Disallowed = r.Form.Get("disallowed")
		allowed, err := ParseList(data.Allowed)
		if err != nil {
			data.Error = "Allowed IPs: " + err.Error()
		}
		var disallowed = allowed[:0:0]
		if data.Error == "" {
			disallowed, err = ParseList(data.Disallowed)
			if err != nil {
				data.Error = "Disallowed IPs: " + err.Error()
			}
		}
		switch {
		case data.Error != "":
			status = http.StatusBadRequest
		case len(allowed) == 0:
			data.Error = "Enter at least one allowed IP address or block."
			status = http.StatusBadRequest
		default:
			res := Calculate(allowed, disallowed)
			data.Line = strings.TrimRight("AllowedIPs = "+res.String(), " ")
			data.V4, data.V6 = len(res.V4), len(res.V6)
		}
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; style-src 'nonce-%[1]s'; script-src 'nonce-%[1]s'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
		data.Nonce))
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if err := page.Execute(w, data); err != nil {
		fmt.Fprintln(os.Stderr, "allowedips: render error:", err)
	}
}

func serve(addr string, log io.Writer) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid --server address %q: expected IP:PORT such as 127.0.0.1:8080 or [::1]:8080", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	bound := ln.Addr().(*net.TCPAddr)
	shown := bound.String()
	fmt.Fprintf(log, "Listening on http://%s/  (Ctrl+C to stop)\n", shown)
	if !bound.IP.IsLoopback() {
		fmt.Fprintln(log, "Note: this address is not loopback-only; the page has no authentication.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
