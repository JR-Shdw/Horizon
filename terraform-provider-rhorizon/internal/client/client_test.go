// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeClient wires a *Client to a httptest.Server. Each test provides
// its own handler, no shared state, no global vault.
func newFakeClient(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := New(srv.URL, "rh_test_token")
	return c, srv.Close
}

func TestNew_TrimsTrailingSlash(t *testing.T) {
	c := New("https://vault.example.com///", "rh_x")
	if c.addr != "https://vault.example.com" {
		t.Fatalf("addr not trimmed: %q", c.addr)
	}
	if c.token != "rh_x" {
		t.Fatalf("token mismatch: %q", c.token)
	}
	if c.http == nil || c.http.Timeout == 0 {
		t.Fatalf("http client must have timeout configured")
	}
}

func TestDoJSON_SetsAuthAndContentType(t *testing.T) {
	var sawAuth, sawCT, sawAccept string
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawCT = r.Header.Get("Content-Type")
		sawAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer stop()

	err := c.doJSON(context.Background(), "POST", "/x", map[string]string{"k": "v"}, nil)
	if err != nil {
		t.Fatalf("doJSON unexpected err: %v", err)
	}
	if sawAuth != "Bearer rh_test_token" {
		t.Errorf("Authorization header = %q, want Bearer rh_test_token", sawAuth)
	}
	if sawCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", sawCT)
	}
	if sawAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", sawAccept)
	}
}

func TestDoJSON_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if err := c.doJSON(context.Background(), "GET", "/x", nil, nil); err != nil {
		t.Fatalf("doJSON unexpected err: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization header present with empty token: %q", sawAuth)
	}
}

func TestDoJSON_NoContentTypeWhenNoBody(t *testing.T) {
	var sawCT string
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		sawCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	if err := c.doJSON(context.Background(), "GET", "/x", nil, nil); err != nil {
		t.Fatalf("doJSON unexpected err: %v", err)
	}
	if sawCT != "" {
		t.Errorf("Content-Type set on GET without body: %q", sawCT)
	}
}

func TestDoJSON_UnmarshalsResponse(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":"hello","n":42}`))
	})
	defer stop()

	var out struct {
		Value string `json:"value"`
		N     int    `json:"n"`
	}
	if err := c.doJSON(context.Background(), "GET", "/x", nil, &out); err != nil {
		t.Fatalf("doJSON err: %v", err)
	}
	if out.Value != "hello" || out.N != 42 {
		t.Errorf("unmarshaled = %+v", out)
	}
}

func TestDoJSON_OutNilWith2xx(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer stop()
	if err := c.doJSON(context.Background(), "DELETE", "/x", nil, nil); err != nil {
		t.Fatalf("204 with nil out should not error: %v", err)
	}
}

func TestDoJSON_ErrorMapping_FastAPIDetail(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"namespace not found"}`))
	})
	defer stop()

	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	if err == nil {
		t.Fatalf("expected error on 404")
	}
	var rerr *Error
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if rerr.Status != 404 {
		t.Errorf("Status = %d, want 404", rerr.Status)
	}
	if rerr.Detail != "namespace not found" {
		t.Errorf("Detail = %q, want 'namespace not found'", rerr.Detail)
	}
	if !strings.Contains(rerr.Error(), "[rhorizon 404]") {
		t.Errorf("Error() should include 'rhorizon 404': %s", rerr.Error())
	}
}

func TestDoJSON_ErrorMapping_NonJSONBody(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  rate limited please retry\n"))
	})
	defer stop()

	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	var rerr *Error
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if rerr.Status != 500 {
		t.Errorf("Status = %d, want 500", rerr.Status)
	}
	if rerr.Detail != "rate limited please retry" {
		t.Errorf("Detail = %q (expected trimmed raw body)", rerr.Detail)
	}
}

func TestDoJSON_ErrorMapping_EmptyBody(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	defer stop()

	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	var rerr *Error
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if rerr.Status != http.StatusBadGateway {
		t.Errorf("Status = %d", rerr.Status)
	}
	if rerr.Detail == "" {
		t.Errorf("Detail should fall through to status text, got empty")
	}
}

func TestDoJSON_MalformedSuccessJSON(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})
	defer stop()

	var out struct{ X string }
	err := c.doJSON(context.Background(), "GET", "/x", nil, &out)
	if err == nil {
		t.Fatalf("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal response") {
		t.Errorf("error should mention unmarshal: %v", err)
	}
}

func TestDoJSON_TransportError(t *testing.T) {
	// Pointing at an addr that immediately closes connections.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close() // drop the server before the request

	c := New(addr, "rh_x")
	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	if err == nil {
		t.Fatalf("expected transport error after server close")
	}
	if !strings.Contains(err.Error(), "http:") {
		t.Errorf("expected 'http:' prefix in transport err: %v", err)
	}
}

func TestDoJSON_ContextCancelled(t *testing.T) {
	c, stop := newFakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Slow server, request is meant to be cancelled before this lands.
		select {}
	})
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.doJSON(ctx, "GET", "/x", nil, nil)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestDoJSON_MarshalErrorBody(t *testing.T) {
	c := New("http://127.0.0.1:1", "rh_x") // unreachable, won't be hit
	// channels are not JSON-encodable, marshal must fail before the wire.
	err := c.doJSON(context.Background(), "POST", "/x", make(chan int), nil)
	if err == nil {
		t.Fatalf("expected marshal error")
	}
	if !strings.Contains(err.Error(), "marshal request body") {
		t.Errorf("err should mention marshal: %v", err)
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"404 Error", &Error{Status: 404}, true},
		{"500 Error", &Error{Status: 500}, false},
		{"wrapped 404", fmt.Errorf("ctx: %w", &Error{Status: 404}), true},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNotFound(tc.err); got != tc.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	e := &Error{Status: 403, Detail: "forbidden"}
	if got := e.Error(); got != "[rhorizon 403] forbidden" {
		t.Errorf("Error() = %q", got)
	}
}
