// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

// Package provider wires up the Terraform plugin framework :
// configure block, resource list, data source list.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/JR-Shdw/Horizon/terraform-provider-rhorizon/internal/client"
)

var _ provider.Provider = (*rhProvider)(nil)

type rhProvider struct {
	version string
}

// New is wired from main.go ; the version flows into the Schema's
// description so users can sanity-check what they ran.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &rhProvider{version: version}
	}
}

// Metadata, provider type name + version surfaced in `terraform version`.
func (p *rhProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "rhorizon"
	resp.Version = p.version
}

// Configure block schema. Two required fields (address + token) plus
// optional CA cert. Falls back to env vars RHORIZON_ADDR and
// RHORIZON_TOKEN when the HCL doesn't set them.
type providerConfig struct {
	Address types.String `tfsdk:"address"`
	Token   types.String `tfsdk:"token"`
}

func (p *rhProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Resurgamus Horizon vault as code. " +
			"Provider version: " + p.version,
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Optional: true,
				Description: "Vault base URL, e.g. https://vault.example.com. " +
					"Falls back to RHORIZON_ADDR if not set in HCL.",
			},
			"token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Bearer token (format rh_...). Required scope " +
					"depends on the resources/data sources you use ; admin:rw " +
					"covers everything. Falls back to RHORIZON_TOKEN env.",
			},
		},
	}
}

// Configure builds a *client.Client and stuffs it into the resp so
// every Resource / DataSource gets it via their Configure method.
func (p *rhProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	addr := cfg.Address.ValueString()
	if addr == "" {
		addr = os.Getenv("RHORIZON_ADDR")
	}
	tok := cfg.Token.ValueString()
	if tok == "" {
		tok = os.Getenv("RHORIZON_TOKEN")
	}

	if addr == "" {
		resp.Diagnostics.AddError(
			"Missing rhorizon address",
			"Set provider attribute `address` or env var RHORIZON_ADDR.",
		)
	}
	if tok == "" {
		resp.Diagnostics.AddError(
			"Missing rhorizon token",
			"Set provider attribute `token` or env var RHORIZON_TOKEN.",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	cli := client.New(addr, tok)
	resp.DataSourceData = cli
	resp.ResourceData = cli
}

func (p *rhProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newSecretResource,
		newNamespaceResource,
	}
}

func (p *rhProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newSecretDataSource,
		newNamespaceDataSource,
	}
}
