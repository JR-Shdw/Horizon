// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/rhorizon_test.go in external-secrets/external-secrets.
//
// Unit tests for the rhorizon-specific bits, error mapping,
// resolveKey splitting, JSON property extraction. Wired against an
// httptest.Server so they don't need a live vault.

package rhorizon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// fakePushRef implements both esv1.PushSecretData and
// esv1.PushSecretRemoteRef with stored string fields, saves us pulling
// in the counterfeiter-generated fakes for these one-line tests.
type fakePushRef struct {
	remoteKey string
	secretKey string
	property  string
}

func (f *fakePushRef) GetRemoteKey() string             { return f.remoteKey }
func (f *fakePushRef) GetSecretKey() string             { return f.secretKey }
func (f *fakePushRef) GetProperty() string              { return f.property }
func (f *fakePushRef) GetMetadata() *apiextensionsv1.JSON { return nil }

// Compile-time satisfaction of both interfaces.
var (
	_ esv1.PushSecretData      = (*fakePushRef)(nil)
	_ esv1.PushSecretRemoteRef = (*fakePushRef)(nil)
)

// fakeVault stands in for a rhorizon API. Each test wires its own
// handler, no global state.
func fakeVault(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	api := newAPIClient(srv.URL, "rh_test", nil, false)
	return &Client{api: api}, srv.Close
}

func TestResolveKey(t *testing.T) {
	cases := []struct {
		in            string
		clientNS      string
		wantName      string
		wantNamespace string
	}{
		{"claude/db-password", "", "db-password", "claude"},
		{"db-password", "default", "db-password", "default"},
		{"db-password", "", "db-password", ""},
		{"a/b/c", "", "b/c", "a"}, // first slash wins
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			cli := &Client{namespace: c.clientNS}
			n, ns := cli.resolveKey(c.in)
			if n != c.wantName || ns != c.wantNamespace {
				t.Fatalf("got (%q, %q), want (%q, %q)", n, ns, c.wantName, c.wantNamespace)
			}
		})
	}
}

func TestGetSecret_Plain(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "db-password") {
			t.Fatalf("unexpected URL %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "db-password", "namespace": "claude",
			"value": "v0", "version": 1,
		})
	})
	defer stop()
	v, err := cli.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "claude/db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "v0" {
		t.Fatalf("got %q, want v0", v)
	}
}

func TestGetSecret_JSONProperty(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "bundle", "namespace": "ns",
			"value":   `{"user":"alice","password":"sekret","port":5432}`,
			"version": 1,
		})
	})
	defer stop()
	v, err := cli.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key: "ns/bundle", Property: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "sekret" {
		t.Fatalf("got %q, want sekret", v)
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Secret 'x' not found"})
	})
	defer stop()
	_, err := cli.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ns/x"})
	if err == nil {
		t.Fatal("expected error")
	}
	// ESO maps NoSecretError to deletion behavior, we must return the
	// sentinel, not a generic 404.
	if !errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("expected esv1.NoSecretErr, got %v", err)
	}
}

func TestGetSecretMap_JSON(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "bundle", "namespace": "ns",
			"value":   `{"user":"alice","port":5432}`,
			"version": 1,
		})
	})
	defer stop()
	m, err := cli.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ns/bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if string(m["user"]) != "alice" {
		t.Fatalf("user: got %q", m["user"])
	}
	if string(m["port"]) != "5432" {
		t.Fatalf("port: got %q", m["port"])
	}
}

func TestGetSecretMap_Plain(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "k", "namespace": "ns",
			"value": "plaintext", "version": 1,
		})
	})
	defer stop()
	m, err := cli.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ns/k"})
	if err != nil {
		t.Fatal(err)
	}
	if string(m["k"]) != "plaintext" {
		t.Fatalf("got %q", m["k"])
	}
}

func TestPushSecret_CreateThenUpdate(t *testing.T) {
	calls := 0
	cli, stop := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case r.Method == "PUT" && calls == 1:
			// First PUT → 404 → triggers POST fallback
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "not found"})
		case r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u", "name": "k", "version": 1})
		case r.Method == "PUT":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u", "name": "k", "version": 2})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL)
		}
	})
	defer stop()
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: "app"},
		Data:       map[string][]byte{"value": []byte("v")},
	}
	ref := &fakePushRef{remoteKey: "ns/k", secretKey: "value"}
	if err := cli.PushSecret(context.Background(), src, ref); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls (PUT 404 + POST), got %d", calls)
	}
}

func TestPushSecret_RejectsMissingSecretKey(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("vault must not be hit when SecretKey is empty")
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer stop()
	src := &corev1.Secret{Data: map[string][]byte{"value": []byte("v")}}
	err := cli.PushSecret(context.Background(), src,
		&fakePushRef{remoteKey: "ns/k", secretKey: ""})
	if err == nil || !strings.Contains(err.Error(), "pushing the whole secret") {
		t.Fatalf("expected reject on empty SecretKey, got %v", err)
	}
}

func TestPushSecret_RejectsMissingKeyInSource(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("vault must not be hit when SecretKey is missing in source")
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer stop()
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: "app"},
		Data:       map[string][]byte{"otherkey": []byte("v")},
	}
	err := cli.PushSecret(context.Background(), src,
		&fakePushRef{remoteKey: "ns/k", secretKey: "missingkey"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected key-not-found error, got %v", err)
	}
}

func TestSecretExists(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantExist bool
	}{
		{"exists", http.StatusOK, true},
		{"missing", http.StatusNotFound, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				if c.status == http.StatusOK {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"name": "k", "namespace": "ns", "value": "v", "version": 1,
					})
				}
			})
			defer stop()
			ok, err := cli.SecretExists(context.Background(),
				&fakePushRef{remoteKey: "ns/k"})
			if err != nil {
				t.Fatal(err)
			}
			if ok != c.wantExist {
				t.Fatalf("got %v, want %v", ok, c.wantExist)
			}
		})
	}
}

func TestValidate_SealedReportedAsUnknown(t *testing.T) {
	cli, stop := fakeVault(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sealed": true})
	})
	defer stop()
	res, err := cli.Validate()
	if err == nil {
		t.Fatal("expected error for sealed vault")
	}
	if res != esv1.ValidationResultUnknown {
		t.Fatalf("got %v, want Unknown", res)
	}
}
