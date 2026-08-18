// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package client

import (
	"context"
	"net/url"
)

// SecretMeta is the shape returned by GET /secrets/ list, never includes
// the plaintext value. Use GetSecret for that.
type SecretMeta struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Namespace     string  `json:"namespace"`
	Version       int     `json:"version"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	DEKRotatedAt  *string `json:"dek_rotated_at"`
}

// SecretValue is GET /secrets/{name}, includes decrypted plaintext.
type SecretValue struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
	Version   int    `json:"version"`
}

// SecretCreateRequest is POST /secrets/.
type SecretCreateRequest struct {
	Name      string                 `json:"name"`
	Value     string                 `json:"value"`
	Namespace string                 `json:"namespace,omitempty"`
	Metadata  map[string]any         `json:"metadata,omitempty"`
	ExpiresAt *string                `json:"expires_at,omitempty"`
	IsHoney   bool                   `json:"is_honey,omitempty"`
}

// SecretCreateResponse, returned on POST /secrets/.
type SecretCreateResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// CreateSecret, POST /api/v1/vault/secrets/
func (c *Client) CreateSecret(ctx context.Context, req SecretCreateRequest) (*SecretCreateResponse, error) {
	var out SecretCreateResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/vault/secrets/", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// secretsPath builds `/api/v1/vault/secrets/{name}` and appends
// `?namespace=<ns>` when ns is non-empty. The same-name-multi-namespace
// API path returns 409 if no `?namespace=` is supplied and more than one
// secret matches the name, so callers that know the namespace MUST pass it.
func secretsPath(name, namespace string) string {
	p := "/api/v1/vault/secrets/" + url.PathEscape(name)
	if namespace != "" {
		p += "?namespace=" + url.QueryEscape(namespace)
	}
	return p
}

// GetSecret, GET /api/v1/vault/secrets/{name}[?namespace=<ns>]
func (c *Client) GetSecret(ctx context.Context, name, namespace string) (*SecretValue, error) {
	var out SecretValue
	if err := c.doJSON(ctx, "GET", secretsPath(name, namespace), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateSecret, PUT /api/v1/vault/secrets/{name}[?namespace=<ns>]. New
// DEK minted server-side.
func (c *Client) UpdateSecret(ctx context.Context, name, namespace, value string) (*SecretCreateResponse, error) {
	var out SecretCreateResponse
	body := struct {
		Value string `json:"value"`
	}{Value: value}
	if err := c.doJSON(ctx, "PUT", secretsPath(name, namespace), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSecret, DELETE /api/v1/vault/secrets/{name}[?namespace=<ns>].
// Behaviour depends on the namespace's delete_protection mode (see
// concepts/rbac.md). For protected mode, body must carry 2FA proof.
func (c *Client) DeleteSecret(ctx context.Context, name, namespace string, body any) error {
	return c.doJSON(ctx, "DELETE", secretsPath(name, namespace), body, nil)
}
