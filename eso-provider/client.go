// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/client.go in external-secrets/external-secrets.
//
// SecretsClient implementation. ESO calls these methods on every
// ExternalSecret reconciliation.

package rhorizon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// Client implements esv1.SecretsClient against a single rhorizon
// vault. One Client per (SecretStore, namespace) pair.
type Client struct {
	api       *apiClient
	namespace string // optional default namespace prefix
}

var _ esv1.SecretsClient = (*Client)(nil)

// resolveKey splits a remoteRef.Key into (name, namespace). Two forms :
//
//	"claude/db-password"            → ("db-password", "claude")
//	"db-password"                   → ("db-password", c.namespace)
//
// The second form requires the SecretStore to declare a default
// namespace ; without one, we fall back to the vault's "default" ns.
func (c *Client) resolveKey(key string) (name, ns string) {
	if i := strings.Index(key, "/"); i >= 0 {
		return key[i+1:], key[:i]
	}
	return key, c.namespace
}

// GetSecret reads a single secret. The remoteRef.Property is honored
// when the secret value is JSON, we extract `Property` from the
// decoded object. Use cases : a single rhorizon secret holding a JSON
// blob with multiple subfields (e.g. DB connection bundle).
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	name, ns := c.resolveKey(ref.Key)
	s, err := c.api.getSecret(ctx, name, ns)
	if err != nil {
		if isNotFound(err) {
			return nil, esv1.NoSecretErr
		}
		return nil, err
	}
	if ref.Property == "" {
		return []byte(s.Value), nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(s.Value), &obj); err != nil {
		return nil, fmt.Errorf("property %q requested but value is not JSON: %w", ref.Property, err)
	}
	v, ok := obj[ref.Property]
	if !ok {
		return nil, fmt.Errorf("property %q not found", ref.Property)
	}
	switch x := v.(type) {
	case string:
		return []byte(x), nil
	default:
		buf, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}
}

// GetSecretMap returns the secret as a map[string][]byte. When the
// stored value is JSON, every top-level key becomes an entry. When
// the value is plain text, the only entry is keyed by the secret's
// short name.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	name, ns := c.resolveKey(ref.Key)
	s, err := c.api.getSecret(ctx, name, ns)
	if err != nil {
		if isNotFound(err) {
			return nil, esv1.NoSecretErr
		}
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(s.Value), &obj); err == nil {
		out := make(map[string][]byte, len(obj))
		for k, v := range obj {
			switch x := v.(type) {
			case string:
				out[k] = []byte(x)
			default:
				buf, err := json.Marshal(v)
				if err != nil {
					return nil, err
				}
				out[k] = buf
			}
		}
		return out, nil
	}
	// Plain string value, return a single-entry map keyed by name.
	return map[string][]byte{name: []byte(s.Value)}, nil
}

// GetAllSecrets supports the find-by-name pattern. ESO calls this with
// either a Path (interpreted as the rhorizon namespace) or a Name
// regex. We use the path as the namespace filter, then in-memory
// regex-filter the names.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	ns := c.namespace
	if ref.Path != nil && *ref.Path != "" {
		ns = *ref.Path
	}
	items, err := c.api.listSecrets(ctx, ns)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, m := range items {
		if ref.Name != nil && ref.Name.RegExp != "" {
			matched, err := regexpMatch(ref.Name.RegExp, m.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid name regex: %w", err)
			}
			if !matched {
				continue
			}
		}
		s, err := c.api.getSecret(ctx, m.Name, m.Namespace)
		if err != nil {
			return nil, err
		}
		out[m.Name] = []byte(s.Value)
	}
	return out, nil
}

// PushSecret writes/updates a secret in rhorizon. ESO uses this for
// bidirectional sync via the PushSecret CRD.
//
// data.GetSecretKey() selects which entry of the source Kubernetes Secret
// to push. Empty SecretKey (push-the-whole-secret) is not supported, ESO's
// other providers either error or marshal the full Secret as JSON ; we
// pick the explicit-error path to match scaleway and avoid surprising
// callers.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	if data.GetSecretKey() == "" {
		return errors.New("rhorizon: pushing the whole secret is not supported; set spec.data[].match.secretKey")
	}
	value, ok := secret.Data[data.GetSecretKey()]
	if !ok {
		return fmt.Errorf("rhorizon: secret key %q not found in source Secret %s/%s",
			data.GetSecretKey(), secret.Namespace, secret.Name)
	}
	name, ns := c.resolveKey(data.GetRemoteKey())
	return c.api.putSecret(ctx, name, ns, string(value))
}

// DeleteSecret removes the secret. Behaviour depends on the namespace's
// delete_protection mode :
//
//	free      → hard delete
//	soft      → soft-delete + retention window (operator can /restore)
//	protected → API rejects (we don't have the 2FA proof flow here)
//
// Protected namespaces should not be ESO-managed for this reason.
func (c *Client) DeleteSecret(ctx context.Context, ref esv1.PushSecretRemoteRef) error {
	name, ns := c.resolveKey(ref.GetRemoteKey())
	if err := c.api.deleteSecret(ctx, name, ns); err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// SecretExists is a cheap probe used by PushSecret to decide
// create-vs-update semantics. We use a HEAD-style read.
func (c *Client) SecretExists(ctx context.Context, ref esv1.PushSecretRemoteRef) (bool, error) {
	name, ns := c.resolveKey(ref.GetRemoteKey())
	_, err := c.api.getSecret(ctx, name, ns)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, err
}

// Close is a no-op, the underlying http.Client doesn't hold socket
// state across reconciliations.
func (c *Client) Close(_ context.Context) error {
	return nil
}

// Validate is the per-Client liveness probe. We hit /api/v1/vault/status
// and accept any 2xx as proof of life. The vault may legitimately be
// `sealed: true`, that's still a valid responsive endpoint, but ESO
// has no way to consume sealed vaults so we report degraded.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	ctx, cancel := contextWithTimeout(5)
	defer cancel()
	var status struct {
		Sealed bool `json:"sealed"`
	}
	if err := c.api.doJSON(ctx, "GET", "/api/v1/vault/status", nil, &status); err != nil {
		return esv1.ValidationResultError, err
	}
	if status.Sealed {
		return esv1.ValidationResultUnknown, errors.New("vault is sealed, operator must unseal")
	}
	return esv1.ValidationResultReady, nil
}
