// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package client

import (
	"context"
	"net/url"
)

// Namespace is the row shape from GET /namespaces/{name}.
type Namespace struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	OwnerGroupID      string  `json:"owner_group_id"`
	EnforceMembership bool    `json:"enforce_membership"`
	DeleteProtection  string  `json:"delete_protection"` // free | soft | protected
	ArchivedAt        *string `json:"archived_at"`
	CreatedBy         *string `json:"created_by"`
	CreatedAt         *string `json:"created_at"`
	SecretCount       int     `json:"secret_count,omitempty"` // only on get-one
}

// NamespaceCreateRequest, body for POST /namespaces/.
type NamespaceCreateRequest struct {
	Name              string `json:"name"`
	OwnerGroupID      string `json:"owner_group_id"`
	EnforceMembership bool   `json:"enforce_membership"`
	DeleteProtection  string `json:"delete_protection,omitempty"` // defaults to "free" server-side
	// 2FA proof fields (sent if the vault has 2FA configured) :
	Challenge        string         `json:"challenge,omitempty"`
	TOTPCode         string         `json:"totp_code,omitempty"`
	YubikeyResponse  string         `json:"yubikey_response,omitempty"`
	WebAuthnResponse map[string]any `json:"webauthn_response,omitempty"`
}

// NamespaceUpdateRequest, body for PUT /namespaces/{name}. Note that
// `name` is immutable post-creation ; the path carries the current name
// and the body holds only the mutable fields.
type NamespaceUpdateRequest struct {
	OwnerGroupID      *string `json:"owner_group_id,omitempty"`
	EnforceMembership *bool   `json:"enforce_membership,omitempty"`
	DeleteProtection  *string `json:"delete_protection,omitempty"`
	// 2FA proof fields :
	Challenge        string         `json:"challenge,omitempty"`
	TOTPCode         string         `json:"totp_code,omitempty"`
	YubikeyResponse  string         `json:"yubikey_response,omitempty"`
	WebAuthnResponse map[string]any `json:"webauthn_response,omitempty"`
}

// CreateNamespace, POST /api/v1/vault/namespaces/.
func (c *Client) CreateNamespace(ctx context.Context, req NamespaceCreateRequest) (*Namespace, error) {
	var out Namespace
	if err := c.doJSON(ctx, "POST", "/api/v1/vault/namespaces/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetNamespace, GET /api/v1/vault/namespaces/{name}.
func (c *Client) GetNamespace(ctx context.Context, name string) (*Namespace, error) {
	var out Namespace
	if err := c.doJSON(ctx, "GET", "/api/v1/vault/namespaces/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateNamespace, PUT /api/v1/vault/namespaces/{name}.
func (c *Client) UpdateNamespace(ctx context.Context, name string, req NamespaceUpdateRequest) (*Namespace, error) {
	var out Namespace
	if err := c.doJSON(ctx, "PUT", "/api/v1/vault/namespaces/"+url.PathEscape(name), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ArchiveNamespace, DELETE /api/v1/vault/namespaces/{name} (soft archive).
func (c *Client) ArchiveNamespace(ctx context.Context, name string, body any) error {
	return c.doJSON(ctx, "DELETE", "/api/v1/vault/namespaces/"+url.PathEscape(name), body, nil)
}
