// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/JR-Shdw/Horizon/terraform-provider-rhorizon/internal/client"
)

var (
	_ resource.Resource                = (*namespaceResource)(nil)
	_ resource.ResourceWithImportState = (*namespaceResource)(nil)
)

type namespaceResource struct {
	cli *client.Client
}

func newNamespaceResource() resource.Resource {
	return &namespaceResource{}
}

type namespaceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	OwnerGroupID      types.String `tfsdk:"owner_group_id"`
	EnforceMembership types.Bool   `tfsdk:"enforce_membership"`
	DeleteProtection  types.String `tfsdk:"delete_protection"`
}

func (r *namespaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (r *namespaceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	cli, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("provider data type", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.cli = cli
}

func (r *namespaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An RBAC-owned namespace (Phase A). The two security " +
			"flags (enforce_membership, delete_protection) are one-way " +
			"ratchets at the DB level, once raised they cannot be " +
			"relaxed. Terraform will refuse to plan a relaxing change.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side UUID of the namespace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Namespace name. **Immutable post-creation**, " +
					"renaming would invalidate the AAD on every secret.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"owner_group_id": schema.StringAttribute{
				Required:    true,
				Description: "UUID of the vault_groups row that owns this namespace.",
			},
			"enforce_membership": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Strict RBAC mode, every read/write checks live group membership. **One-way ratchet** : false → true allowed, true → false rejected with 423 Locked.",
			},
			"delete_protection": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("free"),
				Description: "Deletion mode for secrets in this namespace : " +
					"`free` (hard delete), `soft` (soft-delete + retention + " +
					"restore), or `protected` (admin + 2FA + extended " +
					"retention). **One-way ratchet** : free → soft → " +
					"protected, never backwards.",
			},
		},
	}
}

func (r *namespaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan namespaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.cli.CreateNamespace(ctx, client.NamespaceCreateRequest{
		Name:              plan.Name.ValueString(),
		OwnerGroupID:      plan.OwnerGroupID.ValueString(),
		EnforceMembership: plan.EnforceMembership.ValueBool(),
		DeleteProtection:  plan.DeleteProtection.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create namespace", err.Error())
		return
	}

	plan.ID = types.StringValue(out.ID)
	plan.EnforceMembership = types.BoolValue(out.EnforceMembership)
	plan.DeleteProtection = types.StringValue(out.DeleteProtection)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *namespaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state namespaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.cli.GetNamespace(ctx, state.Name.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read namespace", err.Error())
		return
	}
	state.ID = types.StringValue(out.ID)
	state.OwnerGroupID = types.StringValue(out.OwnerGroupID)
	state.EnforceMembership = types.BoolValue(out.EnforceMembership)
	state.DeleteProtection = types.StringValue(out.DeleteProtection)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *namespaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state namespaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Refuse to plan a relaxing change at the client level, gives a
	// nicer error than letting the server return 423 Locked.
	if state.EnforceMembership.ValueBool() && !plan.EnforceMembership.ValueBool() {
		resp.Diagnostics.AddError(
			"enforce_membership is set-once",
			"Cannot relax true → false. Recovery : create a new namespace in agnostic mode and migrate secrets.",
		)
		return
	}
	rank := map[string]int{"free": 0, "soft": 1, "protected": 2}
	oldRank := rank[state.DeleteProtection.ValueString()]
	newRank := rank[plan.DeleteProtection.ValueString()]
	if newRank < oldRank {
		resp.Diagnostics.AddError(
			"delete_protection is one-way",
			fmt.Sprintf("Cannot relax %s → %s. Recovery : create a new namespace and migrate secrets.",
				state.DeleteProtection.ValueString(), plan.DeleteProtection.ValueString()),
		)
		return
	}

	owner := plan.OwnerGroupID.ValueString()
	enforce := plan.EnforceMembership.ValueBool()
	dp := plan.DeleteProtection.ValueString()
	out, err := r.cli.UpdateNamespace(ctx, state.Name.ValueString(), client.NamespaceUpdateRequest{
		OwnerGroupID:      &owner,
		EnforceMembership: &enforce,
		DeleteProtection:  &dp,
	})
	if err != nil {
		resp.Diagnostics.AddError("update namespace", err.Error())
		return
	}
	plan.ID = types.StringValue(out.ID)
	plan.EnforceMembership = types.BoolValue(out.EnforceMembership)
	plan.DeleteProtection = types.StringValue(out.DeleteProtection)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *namespaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state namespaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.cli.ArchiveNamespace(ctx, state.Name.ValueString(), nil); err != nil {
		if client.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("archive namespace", err.Error())
		return
	}
}

func (r *namespaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
