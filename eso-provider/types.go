// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to apis/externalsecrets/v1/secretstore_rhorizon_types.go
// in external-secrets/external-secrets.

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// RhorizonProvider configures access to a Resurgamus Horizon vault.
type RhorizonProvider struct {
	// Vault base URL, e.g. https://vault.example.com
	// +kubebuilder:validation:Required
	Address string `json:"address"`

	// Authentication block. Currently only token-from-secret is supported ;
	// the `Auth` shape leaves room for future modes (mTLS, k8s SA, etc.).
	// +kubebuilder:validation:Required
	Auth RhorizonAuth `json:"auth"`

	// CABundle is an optional PEM-encoded CA bundle that the controller
	// will trust when calling the vault. Useful when the vault sits
	// behind an internal CA (cert-manager root, private PKI). Mutually
	// exclusive with InsecureSkipTLSVerify.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// InsecureSkipTLSVerify disables TLS validation. **Use only for
	// dev/test**, in production, supply CABundle.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// Namespace narrows the vault namespace scope for this store. When
	// set, ExternalSecret keys are interpreted relative to this
	// namespace and PushSecret targets it. When empty, keys must be
	// fully-qualified (`namespace/name`).
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// RhorizonAuth carries the authentication material. Today only a
// SecretRef-backed bearer token is supported.
type RhorizonAuth struct {
	// TokenSecretRef points at a Kubernetes Secret that holds the
	// bearer token in the referenced key. Recommended : create the
	// Secret with mode 0400 and a tight RBAC policy.
	// +kubebuilder:validation:Required
	TokenSecretRef esmeta.SecretKeySelector `json:"tokenSecretRef"`
}
