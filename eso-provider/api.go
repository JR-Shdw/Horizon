// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/api.go in external-secrets/external-secrets.
//
// Thin HTTP wrapper around the rhorizon REST API. Mirrors the
// terraform-provider-rhorizon's internal/client/ package, kept
// inline here so the upstream PR is self-contained (no internal/
// imports across packages).

package rhorizon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiClient struct {
	addr  string
	token string
	http  *http.Client
}

func newAPIClient(addr, token string, caBundle []byte, insecure bool) *apiClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, // honored only when explicit
		},
	}
	if len(caBundle) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBundle) {
			tr.TLSClientConfig.RootCAs = pool
		}
	}
	return &apiClient{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		},
	}
}

// apiError is returned for any non-2xx response. Carries the FastAPI
// "detail" field plus the raw HTTP status.
type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("[rhorizon %d] %s", e.Status, e.Detail)
}

// isNotFound is the convenience branch helper used throughout the
// SecretsClient implementation.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if ae, ok := err.(*apiError); ok {
		return ae.Status == 404
	}
	return false
}

func (c *apiClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
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
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(respBody) == 0 {
			return nil
		}
		return json.Unmarshal(respBody, out)
	}

	var det struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(respBody, &det)
	if det.Detail == "" {
		det.Detail = strings.TrimSpace(string(respBody))
		if det.Detail == "" {
			det.Detail = resp.Status
		}
	}
	return &apiError{Status: resp.StatusCode, Detail: det.Detail}
}

// secretValue is GET /secrets/{name}.
type secretValue struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
	Version   int    `json:"version"`
}

func (c *apiClient) getSecret(ctx context.Context, name, namespace string) (*secretValue, error) {
	path := "/api/v1/vault/secrets/" + url.PathEscape(name)
	if namespace != "" {
		path += "?namespace=" + url.QueryEscape(namespace)
	}
	var out secretValue
	if err := c.doJSON(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type secretCreateBody struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Namespace string `json:"namespace,omitempty"`
}

func (c *apiClient) putSecret(ctx context.Context, name, namespace, value string) error {
	// Try update first ; if the secret doesn't exist, create.
	updateBody := struct {
		Value string `json:"value"`
	}{Value: value}
	err := c.doJSON(ctx, "PUT", "/api/v1/vault/secrets/"+url.PathEscape(name), updateBody, nil)
	if err == nil {
		return nil
	}
	if !isNotFound(err) {
		return err
	}
	return c.doJSON(ctx, "POST", "/api/v1/vault/secrets/", secretCreateBody{
		Name:      name,
		Value:     value,
		Namespace: namespace,
	}, nil)
}

func (c *apiClient) deleteSecret(ctx context.Context, name, namespace string) error {
	path := "/api/v1/vault/secrets/" + url.PathEscape(name)
	if namespace != "" {
		path += "?namespace=" + url.QueryEscape(namespace)
	}
	return c.doJSON(ctx, "DELETE", path, nil, nil)
}

// secretMeta is GET /secrets/ list (no plaintext).
type secretMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (c *apiClient) listSecrets(ctx context.Context, namespace string) ([]secretMeta, error) {
	path := "/api/v1/vault/secrets/"
	if namespace != "" {
		path += "?namespace=" + url.QueryEscape(namespace)
	}
	var resp struct {
		Items []secretMeta `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}
