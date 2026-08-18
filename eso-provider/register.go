// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to pkg/register/rhorizon.go in external-secrets/external-secrets.
//
// Build-tag gated registration entry. The `rhorizon` build tag (or the
// catch-all `all_providers`) wires this provider into the ESO binary.
// Without one of those tags, the file is silently excluded and the
// provider is not available, same pattern as scaleway, vault, etc.
//
// Locally we keep the file co-located with the rest of the provider
// source so the upstream PR drop is a single directory walk. Reviewers
// move it to its target path per the table in README.md.

//go:build rhorizon || all_providers

package register

import (
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	rhorizon "github.com/external-secrets/external-secrets/providers/v1/rhorizon"
)

func init() {
	esv1.Register(rhorizon.NewProvider(), rhorizon.ProviderSpec(), rhorizon.MaintenanceStatus())
}
