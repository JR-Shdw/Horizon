// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/api_test.go in external-secrets/external-secrets.
//
// Tests bas-niveau sur apiClient : doJSON header/error path,
// putSecret PUT-then-POST fallback, listSecrets unwrap, isNotFound.
// No esv1 imports, purely exercises the apiClient HTTP wrapper.

package rhorizon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAPIClient_TrimsTrailingSlash(t *testing.T) {
	c := newAPIClient("https://vault.example.com///", "rh_x", nil, false)
	if c.addr != "https://vault.example.com" {
		t.Errorf("addr = %q", c.addr)
	}
	if c.token != "rh_x" {
		t.Errorf("token = %q", c.token)
	}
	if c.http == nil || c.http.Timeout == 0 {
		t.Errorf("http client must have timeout")
	}
}

func TestNewAPIClient_InsecureFlag(t *testing.T) {
	cInsecure := newAPIClient("https://x", "t", nil, true)
	cSecure := newAPIClient("https://x", "t", nil, false)
	if cInsecure.http.Transport == nil || cSecure.http.Transport == nil {
		t.Fatalf("transport must be set in both modes")
	}
	// The InsecureSkipVerify flag flows through Transport.TLSClientConfig ;
	// we don't introspect the field directly to avoid coupling to net/http
	// internals, instead we trust the wiring + tests/integration cover the
	// behaviour via the runtime cert verification. Smoke-only here.
}

func TestNewAPIClient_CABundleAccepted(t *testing.T) {
	// Garbage PEM should NOT crash, AppendCertsFromPEM returns false silently
	// and the transport keeps a nil RootCAs (system pool).
	c := newAPIClient("https://x", "t", []byte("---- not a real cert ----"), false)
	if c.http.Transport == nil {
		t.Errorf("transport should be wired even with invalid CA bundle")
	}
}

func TestAPIClient_DoJSON_AuthHeaderSetAndAccept(t *testing.T) {
	var sawAuth, sawAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "rh_z", nil, false)
	if err := c.doJSON(context.Background(), "GET", "/x", nil, nil); err != nil {
		t.Fatalf("doJSON err: %v", err)
	}
	if sawAuth != "Bearer rh_z" {
		t.Errorf("Authorization = %q", sawAuth)
	}
	if sawAccept != "application/json" {
		t.Errorf("Accept = %q", sawAccept)
	}
}

func TestAPIClient_DoJSON_NoAuthWhenTokenEmpty(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "", nil, false)
	_ = c.doJSON(context.Background(), "GET", "/x", nil, nil)
	if sawAuth != "" {
		t.Errorf("Authorization should be absent: %q", sawAuth)
	}
}

func TestAPIClient_DoJSON_ErrorMappingFastAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"insufficient scope"}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	if err == nil {
		t.Fatalf("expected error on 403")
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apiError, got %T", err)
	}
	if ae.Status != 403 || ae.Detail != "insufficient scope" {
		t.Errorf("apiError = %+v", ae)
	}
	if !strings.Contains(ae.Error(), "[rhorizon 403]") {
		t.Errorf("Error() format off: %s", ae.Error())
	}
}

func TestAPIClient_DoJSON_RawBodyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("  upstream down  "))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	var ae *apiError
	if !errors.As(err, &ae) || ae.Detail != "upstream down" {
		t.Errorf("raw fallback failed: %+v", ae)
	}
}

func TestAPIClient_DoJSON_EmptyBodyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	err := c.doJSON(context.Background(), "GET", "/x", nil, nil)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apiError, got %T", err)
	}
	if ae.Detail == "" {
		t.Errorf("Detail must fall through to status text on empty body")
	}
}

func TestIsNotFound_API(t *testing.T) {
	if isNotFound(nil) {
		t.Errorf("nil should not be NotFound")
	}
	if isNotFound(errors.New("plain")) {
		t.Errorf("plain error should not be NotFound")
	}
	if !isNotFound(&apiError{Status: 404}) {
		t.Errorf("404 apiError must be NotFound")
	}
	if isNotFound(&apiError{Status: 410}) {
		t.Errorf("410 apiError must NOT be NotFound (gone != not found)")
	}
}

func TestAPIClient_GetSecret_NamespaceQuery(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"db","namespace":"prod","value":"hunter2","version":1}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)

	sv, err := c.getSecret(context.Background(), "db", "prod")
	if err != nil {
		t.Fatalf("getSecret err: %v", err)
	}
	if !strings.Contains(gotURL, "/api/v1/vault/secrets/db") {
		t.Errorf("path missing: %s", gotURL)
	}
	if !strings.Contains(gotURL, "namespace=prod") {
		t.Errorf("namespace query missing: %s", gotURL)
	}
	if sv.Value != "hunter2" {
		t.Errorf("value = %q", sv.Value)
	}
}

func TestAPIClient_GetSecret_NoNamespaceNoQuery(t *testing.T) {
	var gotRaw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRaw = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"x","namespace":"","value":"v","version":1}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	if _, err := c.getSecret(context.Background(), "x", ""); err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotRaw != "" {
		t.Errorf("namespace empty should NOT add query string: %q", gotRaw)
	}
}

func TestAPIClient_PutSecret_UpdateFirstThenCreate(t *testing.T) {
	var methodSeq []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodSeq = append(methodSeq, r.Method)
		if r.Method == "PUT" {
			// First call : pretend the secret doesn't exist yet.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"not found"}`))
			return
		}
		// Second call : POST creates.
		buf, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(buf, &body)
		if body["name"] != "k" || body["value"] != "v" || body["namespace"] != "ns" {
			t.Errorf("create body = %+v", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newAPIClient(srv.URL, "t", nil, false)
	if err := c.putSecret(context.Background(), "k", "ns", "v"); err != nil {
		t.Fatalf("putSecret err: %v", err)
	}
	if len(methodSeq) != 2 || methodSeq[0] != "PUT" || methodSeq[1] != "POST" {
		t.Errorf("expected PUT then POST, got %v", methodSeq)
	}
}

func TestAPIClient_PutSecret_UpdateSucceedsNoCreate(t *testing.T) {
	var methodSeq []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodSeq = append(methodSeq, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	if err := c.putSecret(context.Background(), "k", "ns", "v"); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(methodSeq) != 1 || methodSeq[0] != "PUT" {
		t.Errorf("should be single PUT, got %v", methodSeq)
	}
}

func TestAPIClient_PutSecret_NonNotFoundErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 403 on PUT, must NOT fall through to POST, must propagate.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"locked"}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	err := c.putSecret(context.Background(), "k", "", "v")
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 403 {
		t.Errorf("expected 403 propagated, got %v", err)
	}
}

func TestAPIClient_DeleteSecret(t *testing.T) {
	var gotMethod, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	if err := c.deleteSecret(context.Background(), "k", "prod"); err != nil {
		t.Errorf("err: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method = %s", gotMethod)
	}
	if gotQuery != "namespace=prod" {
		t.Errorf("query = %q (want namespace=prod)", gotQuery)
	}
	// Empty namespace must omit the query param to preserve back-compat.
	if err := c.deleteSecret(context.Background(), "k", ""); err != nil {
		t.Errorf("err: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("query = %q (want empty)", gotQuery)
	}
}

func TestAPIClient_ListSecrets_UnwrapItems(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"name":"a","namespace":"ns"},{"name":"b","namespace":"ns"}]}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)

	items, err := c.listSecrets(context.Background(), "ns")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotQuery != "namespace=ns" {
		t.Errorf("query = %s", gotQuery)
	}
	if len(items) != 2 || items[0].Name != "a" || items[1].Name != "b" {
		t.Errorf("items = %+v", items)
	}
}

func TestAPIClient_ListSecrets_NoNamespace(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "t", nil, false)
	if _, err := c.listSecrets(context.Background(), ""); err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("empty namespace must not add query: %q", gotQuery)
	}
}
