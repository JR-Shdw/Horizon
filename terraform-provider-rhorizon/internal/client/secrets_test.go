// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateSecret_PostsBodyReturnsIDVersion(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sec-1","name":"db-password","version":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	out, err := c.CreateSecret(context.Background(), SecretCreateRequest{
		Name:      "db-password",
		Value:     "hunter2",
		Namespace: "prod",
		IsHoney:   true,
	})
	if err != nil {
		t.Fatalf("CreateSecret err: %v", err)
	}
	if gotMethod != "POST" || gotPath != "/api/v1/vault/secrets/" {
		t.Errorf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["name"] != "db-password" || gotBody["value"] != "hunter2" ||
		gotBody["namespace"] != "prod" || gotBody["is_honey"] != true {
		t.Errorf("body = %+v", gotBody)
	}
	if out.ID != "sec-1" || out.Version != 1 {
		t.Errorf("out = %+v", out)
	}
}

func TestCreateSecret_OmitsZeroValuedFields(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"sec-2","name":"x","version":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	_, err := c.CreateSecret(context.Background(), SecretCreateRequest{
		Name:  "x",
		Value: "v",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, k := range []string{"namespace", "is_honey", "expires_at", "metadata"} {
		if _, present := gotBody[k]; present {
			t.Errorf("optional zero field %q should be omitted, got %+v", k, gotBody)
		}
	}
}

func TestGetSecret_ReturnsValueAndPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"db-password","namespace":"prod","value":"hunter2","version":3}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	sec, err := c.GetSecret(context.Background(), "db-password", "")
	if err != nil {
		t.Fatalf("GetSecret err: %v", err)
	}
	if gotPath != "/api/v1/vault/secrets/db-password" {
		t.Errorf("path = %s", gotPath)
	}
	if sec.Value != "hunter2" || sec.Version != 3 || sec.Namespace != "prod" {
		t.Errorf("sec = %+v", sec)
	}
}

func TestGetSecret_PathEscapesName(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"weird key","namespace":"default","value":"v","version":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	_, err := c.GetSecret(context.Background(), "weird key", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(gotPath, "weird%20key") {
		t.Errorf("space should be percent-encoded: %s", gotPath)
	}
}

func TestGetSecret_AppendsNamespaceQuery(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"k","namespace":"prod","value":"v","version":1}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "rh_x")
	if _, err := c.GetSecret(context.Background(), "k", "prod"); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(gotURL, "namespace=prod") {
		t.Errorf("missing namespace query: %s", gotURL)
	}
}

func TestUpdateSecret_PutsValueOnly(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sec-1","name":"db-password","version":4}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	out, err := c.UpdateSecret(context.Background(), "db-password", "", "newval")
	if err != nil {
		t.Fatalf("UpdateSecret err: %v", err)
	}
	if gotMethod != "PUT" || gotPath != "/api/v1/vault/secrets/db-password" {
		t.Errorf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["value"] != "newval" {
		t.Errorf("body = %+v (only value should be sent)", gotBody)
	}
	if len(gotBody) != 1 {
		t.Errorf("body should only contain value, got keys = %d: %+v", len(gotBody), gotBody)
	}
	if out.Version != 4 {
		t.Errorf("out.Version = %d", out.Version)
	}
}

func TestDeleteSecret_OkAndError(t *testing.T) {
	t.Run("success-204-no-body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "DELETE" {
				t.Errorf("method = %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		c := New(srv.URL, "rh_x")
		if err := c.DeleteSecret(context.Background(), "x", "", nil); err != nil {
			t.Errorf("expected no error on 204, got %v", err)
		}
	})

	t.Run("404-typed-error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"gone"}`))
		}))
		defer srv.Close()
		c := New(srv.URL, "rh_x")
		err := c.DeleteSecret(context.Background(), "x", "", nil)
		if !IsNotFound(err) {
			t.Errorf("expected NotFound, got %v", err)
		}
	})

	t.Run("with-2fa-proof-body", func(t *testing.T) {
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(buf, &gotBody)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		c := New(srv.URL, "rh_x")
		body := map[string]any{"totp_code": "654321"}
		if err := c.DeleteSecret(context.Background(), "protected-secret", "", body); err != nil {
			t.Errorf("err: %v", err)
		}
		if gotBody["totp_code"] != "654321" {
			t.Errorf("2FA proof not forwarded: %+v", gotBody)
		}
	})
}
