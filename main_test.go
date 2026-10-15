package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRunDrainsInFlightRequestsOnShutdown(t *testing.T) {
	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "done")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, srv, ln) }()

	type result struct {
		body string
		err  error
	}
	res := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		res <- result{string(b), err}
	}()

	<-started
	cancel()

	if r := <-res; r.err != nil || r.body != "done" {
		t.Errorf("in-flight request: %q, %v", r.body, r.err)
	}
	if err := <-runErr; err != nil {
		t.Errorf("run: %v", err)
	}
}

func TestRunReturnsServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if err := run(t.Context(), &http.Server{}, ln); err == nil {
		t.Error("expected error from closed listener")
	}
}
