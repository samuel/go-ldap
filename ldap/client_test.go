package ldap_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/samuel/go-ldap/ldap"
)

// TestClientContextCancel verifies that canceling a request's context unblocks
// it (returning context.Canceled) even though the server never responds.
func TestClientContextCancel(t *testing.T) {
	t.Parallel()
	cliCn, srvCn := net.Pipe()
	defer func() { _ = srvCn.Close() }()
	go func() { _, _ = io.Copy(io.Discard, srvCn) }() // drain the request, never respond
	c := ldap.NewClient(cliCn, false)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		errc <- c.Bind(ctx, "cn=test", []byte("pw"))
	}()

	time.Sleep(50 * time.Millisecond) // let the request register and block on the response
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Bind did not return after context cancel")
	}
}

// TestClientShutdownOnConnLoss verifies that an in-flight request returns an
// error (rather than blocking forever) when the connection is dropped.
func TestClientShutdownOnConnLoss(t *testing.T) {
	t.Parallel()
	cliCn, srvCn := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, srvCn) }() // drain whatever the client sends
	c := ldap.NewClient(cliCn, false)

	ctx := t.Context()
	errc := make(chan error, 1)
	go func() {
		errc <- c.Bind(ctx, "cn=test", []byte("pw"))
	}()

	time.Sleep(50 * time.Millisecond) // let the request reach the wire
	_ = srvCn.Close()                 // drop the connection

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error after connection loss, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not return after connection loss")
	}
}

// TestClientCloseWakesPending verifies that Close() wakes a pending request
// instead of leaking it.
func TestClientCloseWakesPending(t *testing.T) {
	t.Parallel()
	cliCn, srvCn := net.Pipe()
	//nolint:errcheck
	defer srvCn.Close()
	go func() { _, _ = io.Copy(io.Discard, srvCn) }()
	c := ldap.NewClient(cliCn, false)

	ctx := t.Context()
	errc := make(chan error, 1)
	go func() {
		errc <- c.Bind(ctx, "cn=test", []byte("pw"))
	}()

	time.Sleep(50 * time.Millisecond)
	_ = c.Close()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not return after Close")
	}
}

func TestClientBind(t *testing.T) {
	t.Parallel()
	c, err := ldap.Dial(t.Context(), "tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(t.Context(), "cn=test", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(t.Context(), "cn=test", []byte("verysecure")); err != nil {
		t.Fatal(err)
	}
}

func TestClientDelete(t *testing.T) {
	t.Parallel()
	c, err := ldap.Dial(t.Context(), "tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), "cn=test"); err != nil {
		t.Fatal(err)
	}
}

func TestClientSearch(t *testing.T) {
	t.Parallel()
	c, err := ldap.Dial(t.Context(), "tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	req := &ldap.SearchRequest{
		Scope: ldap.ScopeWholeSubtree,
	}
	if res, err := c.Search(t.Context(), req); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	}
}
