// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package client

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

func TestCreateNamespace_SerializesBodyAndReturnsRow(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ns-1","name":"prod","owner_group_id":"g-1","enforce_membership":true,"delete_protection":"protected"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	ns, err := c.CreateNamespace(context.Background(), NamespaceCreateRequest{
		Name:              "prod",
		OwnerGroupID:      "g-1",
		EnforceMembership: true,
		DeleteProtection:  "protected",
	})
	if err != nil {
		t.Fatalf("CreateNamespace err: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %s", gotMethod)
	}
	if gotPath != "/api/v1/vault/namespaces/" {
		t.Errorf("path = %s", gotPath)
	}
	if gotBody["name"] != "prod" || gotBody["owner_group_id"] != "g-1" ||
		gotBody["enforce_membership"] != true || gotBody["delete_protection"] != "protected" {
		t.Errorf("body = %+v", gotBody)
	}
	// 2FA proof fields with omitempty must NOT appear when empty.
	if _, ok := gotBody["totp_code"]; ok {
		t.Errorf("empty totp_code should be omitted from body")
	}
	if ns.ID != "ns-1" || ns.Name != "prod" || ns.OwnerGroupID != "g-1" ||
		!ns.EnforceMembership || ns.DeleteProtection != "protected" {
		t.Errorf("unmarshal = %+v", ns)
	}
}

func TestGetNamespace_PathEscapesName(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ns-2","name":"weird/name","owner_group_id":"g","enforce_membership":false,"delete_protection":"free","secret_count":3}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	ns, err := c.GetNamespace(context.Background(), "weird/name")
	if err != nil {
		t.Fatalf("GetNamespace err: %v", err)
	}
	if gotMethod != "GET" {
		t.Errorf("method = %s", gotMethod)
	}
	// "/" in the name must be percent-encoded so it doesn't break the path.
	if !strings.Contains(gotPath, "weird%2Fname") {
		t.Errorf("path should percent-encode slash: got %s", gotPath)
	}
	if ns.SecretCount != 3 {
		t.Errorf("secret_count = %d", ns.SecretCount)
	}
}

func TestGetNamespace_404IsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"namespace not found"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	_, err := c.GetNamespace(context.Background(), "ghost")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound should be true: %v", err)
	}
	var rerr *Error
	if !errors.As(err, &rerr) || rerr.Status != 404 {
		t.Errorf("expected *Error with 404, got %T %v", err, err)
	}
}

func TestUpdateNamespace_SendsOnlyMutableFields(t *testing.T) {
	var gotMethod, gotPath string
	var raw json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ns-3","name":"prod","owner_group_id":"g-new","enforce_membership":false,"delete_protection":"protected"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	prot := "protected"
	enforce := false
	_, err := c.UpdateNamespace(context.Background(), "prod", NamespaceUpdateRequest{
		EnforceMembership: &enforce,
		DeleteProtection:  &prot,
	})
	if err != nil {
		t.Fatalf("UpdateNamespace err: %v", err)
	}
	if gotMethod != "PUT" {
		t.Errorf("method = %s", gotMethod)
	}
	if gotPath != "/api/v1/vault/namespaces/prod" {
		t.Errorf("path = %s", gotPath)
	}
	// owner_group_id was left nil → must be omitted from the wire body.
	body := string(raw)
	if strings.Contains(body, "owner_group_id") {
		t.Errorf("nil owner_group_id should be omitted, got %s", body)
	}
	if !strings.Contains(body, `"enforce_membership":false`) {
		t.Errorf("enforce_membership should be present and false: %s", body)
	}
	if !strings.Contains(body, `"delete_protection":"protected"`) {
		t.Errorf("delete_protection should be present: %s", body)
	}
}

func TestArchiveNamespace_PutsBodyAndReturnsNoError(t *testing.T) {
	var gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	err := c.ArchiveNamespace(context.Background(), "prod", map[string]any{"totp_code": "123456"})
	if err != nil {
		t.Fatalf("ArchiveNamespace err: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method = %s", gotMethod)
	}
	if gotBody["totp_code"] != "123456" {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestArchiveNamespace_ErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"namespace is protected"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "rh_x")
	err := c.ArchiveNamespace(context.Background(), "prod", nil)
	var rerr *Error
	if !errors.As(err, &rerr) || rerr.Status != 403 {
		t.Errorf("expected 403, got %v", err)
	}
}
