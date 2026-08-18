// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/JR-Shdw/Horizon/terraform-provider-rhorizon/internal/client"
)

var _ datasource.DataSource = (*secretDataSource)(nil)

type secretDataSource struct {
	cli *client.Client
}

func newSecretDataSource() datasource.DataSource {
	return &secretDataSource{}
}

type secretDataModel struct {
	Name      types.String `tfsdk:"name"`
	Value     types.String `tfsdk:"value"`
	Namespace types.String `tfsdk:"namespace"`
	Version   types.Int64  `tfsdk:"version"`
}

func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	cli, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("provider data type", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.cli = cli
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read a secret managed outside this Terraform run " +
			"(e.g. minted by an operator via the UI). Use sparingly, " +
			"prefer `rhorizon_secret` resources for secrets you own.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Secret name to look up.",
			},
			"value": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Plaintext value (decrypted server-side).",
			},
			"namespace": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Containing namespace. Pass it to disambiguate " +
					"same-name secrets across namespaces (the API returns " +
					"409 ambiguous otherwise). Populated on read.",
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "Version counter.",
			},
		},
	}
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg secretDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := d.cli.GetSecret(ctx, cfg.Name.ValueString(), cfg.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("read secret", err.Error())
		return
	}
	cfg.Value = types.StringValue(out.Value)
	cfg.Namespace = types.StringValue(out.Namespace)
	cfg.Version = types.Int64Value(int64(out.Version))
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
