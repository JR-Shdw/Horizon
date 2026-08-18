// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

// Package client wraps the rhorizon REST API for use by the Terraform
// provider. Mirrors the @rhorizon/client TypeScript SDK in shape :
// every API endpoint surfaces as a typed Go method ; non-2xx responses
// produce typed errors callers can branch on.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the HTTP wrapper. Created via New ; sub-resources hung
// directly off its methods (no sub-clients in Go for simplicity).
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// New builds a Client. addr should be the vault base URL (no trailing
// slash). token is the bearer ; can be empty when calling unauth'd
// endpoints (status / health / challenge).
func New(addr, token string) *Client {
	return &Client{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Error is returned for any non-2xx response. Carries the HTTP status
// + the FastAPI-style "detail" field.
type Error struct {
	Status int
	Detail string
	Body   []byte
}

func (e *Error) Error() string {
	return fmt.Sprintf("[rhorizon %d] %s", e.Status, e.Detail)
}

// IsNotFound, convenience helper for the common branch pattern.
func IsNotFound(err error) bool {
	var rerr *Error
	if err == nil {
		return false
	}
	for {
		var ok bool
		rerr, ok = err.(*Error)
		if ok {
			return rerr.Status == 404
		}
		// unwrap if wrapped
		u, hasUnwrap := err.(interface{ Unwrap() error })
		if !hasUnwrap {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(respBody) == 0 {
			return nil
		}
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
		return nil
	}

	// Try to extract the FastAPI-style detail field. Falls through to
	// the raw body on parse failure.
	var detail struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(respBody, &detail)
	if detail.Detail == "" {
		detail.Detail = strings.TrimSpace(string(respBody))
		if detail.Detail == "" {
			detail.Detail = resp.Status
		}
	}
	return &Error{
		Status: resp.StatusCode,
		Detail: detail.Detail,
		Body:   respBody,
	}
}
