// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/JR-Shdw/Horizon/terraform-provider-rhorizon/internal/client"
)

var (
	_ resource.Resource                = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
)

type secretResource struct {
	cli *client.Client
}

func newSecretResource() resource.Resource {
	return &secretResource{}
}

type secretModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Value     types.String `tfsdk:"value"`
	Namespace types.String `tfsdk:"namespace"`
	Version   types.Int64  `tfsdk:"version"`
	IsHoney   types.Bool   `tfsdk:"is_honey"`
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A secret stored in rhorizon. The plaintext value is " +
			"sent over the wire on every plan ; mark `value` sensitive in " +
			"any output to keep it out of logs.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side UUID of the secret row.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Globally unique secret name. Renaming requires " +
					"destroy + recreate (Terraform infers ForceNew via state).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"value": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Plaintext value, encrypted server-side with XChaCha20-Poly1305 + a per-secret DEK.",
			},
			"namespace": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Containing namespace. Defaults to `default` server-side. Changing requires destroy+recreate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "Version counter, bumps on every update.",
			},
			"is_honey": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Mark as honeytoken, any read fires a CRITICAL " +
					"alert. Pick attractive names (prod-pgsql-master) so " +
					"attackers want to read it.",
				PlanModifiers: []planmodifier.Bool{
					// UseStateForUnknown MUST come before RequiresReplace -
					// without it the framework treats an HCL-unset Computed
					// bool as `(known after apply)` on every refresh, which
					// the next RequiresReplace modifier then turns into a
					// destroy/create cycle. Net effect : secrets that
					// omit `is_honey` get recreated (new id, new DEK) on
					// every apply.
					boolplanmodifier.UseStateForUnknown(),
					boolplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.cli.CreateSecret(ctx, client.SecretCreateRequest{
		Name:      plan.Name.ValueString(),
		Value:     plan.Value.ValueString(),
		Namespace: plan.Namespace.ValueString(),
		IsHoney:   plan.IsHoney.ValueBool(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create secret", err.Error())
		return
	}

	plan.ID = types.StringValue(out.ID)
	plan.Version = types.Int64Value(int64(out.Version))
	if plan.Namespace.IsNull() || plan.Namespace.IsUnknown() {
		plan.Namespace = types.StringValue("default")
	}
	if plan.IsHoney.IsNull() || plan.IsHoney.IsUnknown() {
		plan.IsHoney = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.cli.GetSecret(ctx, state.Name.ValueString(), state.Namespace.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read secret", err.Error())
		return
	}
	state.Value = types.StringValue(out.Value)
	state.Namespace = types.StringValue(out.Namespace)
	state.Version = types.Int64Value(int64(out.Version))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.cli.UpdateSecret(ctx, plan.Name.ValueString(), plan.Namespace.ValueString(), plan.Value.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("update secret", err.Error())
		return
	}
	plan.ID = types.StringValue(out.ID)
	plan.Version = types.Int64Value(int64(out.Version))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.cli.DeleteSecret(ctx, state.Name.ValueString(), state.Namespace.ValueString(), nil); err != nil {
		if client.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("delete secret", err.Error())
		return
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
