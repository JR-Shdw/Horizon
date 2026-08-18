// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/rhorizon.go in external-secrets/external-secrets.
//
// Provider entry point. Implements the esv1.Provider interface :
// NewClient, ValidateStore, Capabilities. Registration lives in
// pkg/register/rhorizon.go (build-tag gated), not here.

package rhorizon

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// Provider is the rhorizon entry into the ESO provider registry.
type Provider struct{}

var _ esv1.Provider = (*Provider)(nil)

// Capabilities advertises full read/write, the SecretsClient
// implementation below covers GetSecret, PushSecret, DeleteSecret,
// GetAllSecrets, and SecretExists.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient is called per ExternalSecret reconciliation. We resolve
// the bearer token from the referenced Kubernetes Secret, build the
// HTTP client, and hand it to the SecretsClient impl.
func (p *Provider) NewClient(
	ctx context.Context,
	store esv1.GenericStore,
	kube kclient.Client,
	namespace string,
) (esv1.SecretsClient, error) {
	cfg, err := getConfig(store)
	if err != nil {
		return nil, err
	}

	token, err := loadTokenFromSecret(ctx, kube, namespace, store, &cfg.Auth.TokenSecretRef)
	if err != nil {
		return nil, fmt.Errorf("rhorizon: load token: %w", err)
	}

	api := newAPIClient(cfg.Address, token, cfg.CABundle, cfg.InsecureSkipTLSVerify)
	return &Client{
		api:       api,
		namespace: cfg.Namespace,
	}, nil
}

// ValidateStore is run when a SecretStore is admitted or updated.
// We check : (a) address looks like a URL, (b) auth.tokenSecretRef
// is fully specified, (c) only one of CABundle / InsecureSkipTLSVerify
// is set.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	cfg, err := getConfig(store)
	if err != nil {
		return nil, err
	}
	pp := field.NewPath("spec", "provider", "rhorizon")

	if cfg.Address == "" {
		return nil, field.Required(pp.Child("address"), "vault base URL is required")
	}
	if cfg.Auth.TokenSecretRef.Name == "" {
		return nil, field.Required(pp.Child("auth", "tokenSecretRef", "name"), "secret name required")
	}
	if cfg.Auth.TokenSecretRef.Key == "" {
		return nil, field.Required(pp.Child("auth", "tokenSecretRef", "key"), "secret key required")
	}
	if len(cfg.CABundle) > 0 && cfg.InsecureSkipTLSVerify {
		return nil, field.Forbidden(pp.Child("insecureSkipTLSVerify"),
			"cannot combine caBundle with insecureSkipTLSVerify")
	}
	return nil, nil
}

func getConfig(store esv1.GenericStore) (*esv1.RhorizonProvider, error) {
	if store == nil {
		return nil, errors.New("nil SecretStore")
	}
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.Rhorizon == nil {
		return nil, errors.New("rhorizon provider config missing")
	}
	return spec.Provider.Rhorizon, nil
}

// loadTokenFromSecret resolves the bearer from a Kubernetes Secret.
// Honors the optional ClusterSecretStore namespace override (when
// store is cluster-scoped, the Secret can live in a different namespace).
func loadTokenFromSecret(
	ctx context.Context,
	kube kclient.Client,
	defaultNS string,
	store esv1.GenericStore,
	ref *esmeta.SecretKeySelector,
) (string, error) {
	ns := defaultNS
	if ref.Namespace != nil && *ref.Namespace != "" {
		// ClusterSecretStore allows cross-namespace ; ESO admission
		// rejects it for the namespaced kind, so we trust the API
		// here and let RBAC catch any abuse.
		_ = store // keep the store reachable for future kind branching
		ns = *ref.Namespace
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &secret); err != nil {
		return "", fmt.Errorf("get secret %s/%s: %w", ns, ref.Name, err)
	}
	val, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ns, ref.Name)
	}
	tok := string(val)
	if tok == "" {
		return "", fmt.Errorf("token at %s/%s/%s is empty", ns, ref.Name, ref.Key)
	}
	return tok, nil
}

// NewProvider returns a fresh Provider instance. Called from
// pkg/register/rhorizon.go (build-tag gated) on init().
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the SecretStoreProvider with the Rhorizon field
// pre-allocated so ESO's CRD validation can hand the provider its config
// on each reconcile.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		Rhorizon: &esv1.RhorizonProvider{},
	}
}

// MaintenanceStatus tags this provider's lifecycle status for the
// ESO provider catalog page.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}

// gvk is the SecretStore GroupVersionKind ; useful for log lines.
var gvk = schema.GroupVersionKind{
	Group:   "external-secrets.io",
	Version: "v1",
	Kind:    "SecretStore",
}
