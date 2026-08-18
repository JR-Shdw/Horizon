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

var _ datasource.DataSource = (*namespaceDataSource)(nil)

type namespaceDataSource struct {
	cli *client.Client
}

func newNamespaceDataSource() datasource.DataSource {
	return &namespaceDataSource{}
}

type namespaceDataModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	OwnerGroupID      types.String `tfsdk:"owner_group_id"`
	EnforceMembership types.Bool   `tfsdk:"enforce_membership"`
	DeleteProtection  types.String `tfsdk:"delete_protection"`
	SecretCount       types.Int64  `tfsdk:"secret_count"`
}

func (d *namespaceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (d *namespaceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *namespaceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read an existing namespace's metadata.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side UUID.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Namespace name to look up.",
			},
			"owner_group_id": schema.StringAttribute{
				Computed:    true,
				Description: "UUID of the owning vault_groups row.",
			},
			"enforce_membership": schema.BoolAttribute{
				Computed:    true,
				Description: "Strict RBAC mode flag.",
			},
			"delete_protection": schema.StringAttribute{
				Computed:    true,
				Description: "Deletion mode (free / soft / protected).",
			},
			"secret_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of non-archived secrets currently in this namespace.",
			},
		},
	}
}

func (d *namespaceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg namespaceDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := d.cli.GetNamespace(ctx, cfg.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("read namespace", err.Error())
		return
	}
	cfg.ID = types.StringValue(out.ID)
	cfg.OwnerGroupID = types.StringValue(out.OwnerGroupID)
	cfg.EnforceMembership = types.BoolValue(out.EnforceMembership)
	cfg.DeleteProtection = types.StringValue(out.DeleteProtection)
	cfg.SecretCount = types.Int64Value(int64(out.SecretCount))
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
