// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

// Unit tests for the provider wiring. Couvre Metadata, Schema, et la
// liste des Resources/DataSources expose. Les paths Read/Create/Update/
// Delete des resources demandent l'infra acctest terraform-plugin-framework
// + un vault reel, hors scope batch initial. A elargir dans un sprint
// suivant via providerserver.NewProtocol6WithError + TF_ACC=1.

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	pschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestProvider_Metadata(t *testing.T) {
	p := New("v1.2.3")()
	var resp provider.MetadataResponse
	p.Metadata(context.Background(), provider.MetadataRequest{}, &resp)
	if resp.TypeName != "rhorizon" {
		t.Errorf("TypeName = %q, want rhorizon", resp.TypeName)
	}
	if resp.Version != "v1.2.3" {
		t.Errorf("Version = %q, want v1.2.3", resp.Version)
	}
}

func TestProvider_Schema_HasAddressAndToken(t *testing.T) {
	p := New("dev")()
	var resp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &resp)

	addr, ok := resp.Schema.Attributes["address"].(pschema.StringAttribute)
	if !ok {
		t.Fatalf("address attribute missing or wrong type: %+v", resp.Schema.Attributes["address"])
	}
	if !addr.Optional {
		t.Errorf("address should be Optional (env var fallback)")
	}
	tok, ok := resp.Schema.Attributes["token"].(pschema.StringAttribute)
	if !ok {
		t.Fatalf("token attribute missing or wrong type")
	}
	if !tok.Optional {
		t.Errorf("token should be Optional")
	}
	if !tok.Sensitive {
		t.Errorf("token MUST be Sensitive (it's a bearer)")
	}
}

func TestProvider_Resources_Count(t *testing.T) {
	p := New("dev")()
	rs := p.Resources(context.Background())
	if len(rs) != 2 {
		t.Fatalf("Resources() = %d, want 2 (secret + namespace)", len(rs))
	}
	for i, fn := range rs {
		if fn() == nil {
			t.Errorf("Resources()[%d] factory returned nil", i)
		}
	}
}

func TestProvider_DataSources_Count(t *testing.T) {
	p := New("dev")()
	ds := p.DataSources(context.Background())
	if len(ds) != 2 {
		t.Fatalf("DataSources() = %d, want 2 (secret + namespace)", len(ds))
	}
	for i, fn := range ds {
		if fn() == nil {
			t.Errorf("DataSources()[%d] factory returned nil", i)
		}
	}
}

func TestSecretResource_MetadataAndSchema(t *testing.T) {
	r := newSecretResource()
	var md resource.MetadataResponse
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "rhorizon"}, &md)
	if md.TypeName != "rhorizon_secret" {
		t.Errorf("secret TypeName = %q", md.TypeName)
	}

	var sresp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sresp)
	attrs := sresp.Schema.Attributes
	for _, k := range []string{"id", "name", "value", "namespace", "version", "is_honey"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("secret schema missing attribute %q", k)
		}
	}
	// `value` must be sensitive, plaintext on the wire.
	if v, ok := attrs["value"].(rschema.StringAttribute); !ok || !v.Sensitive {
		t.Errorf("secret.value must be Sensitive: %+v", attrs["value"])
	}
	if v, ok := attrs["name"].(rschema.StringAttribute); !ok || !v.Required {
		t.Errorf("secret.name must be Required")
	}
}

func TestNamespaceResource_MetadataAndSchema(t *testing.T) {
	r := newNamespaceResource()
	var md resource.MetadataResponse
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "rhorizon"}, &md)
	if md.TypeName != "rhorizon_namespace" {
		t.Errorf("namespace TypeName = %q", md.TypeName)
	}

	var sresp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sresp)
	attrs := sresp.Schema.Attributes
	for _, k := range []string{"id", "name", "owner_group_id", "enforce_membership", "delete_protection"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("namespace schema missing attribute %q", k)
		}
	}
	if v, ok := attrs["name"].(rschema.StringAttribute); !ok || !v.Required {
		t.Errorf("namespace.name must be Required")
	}
}

func TestSecretDataSource_MetadataAndSchema(t *testing.T) {
	d := newSecretDataSource()
	var md datasource.MetadataResponse
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "rhorizon"}, &md)
	if md.TypeName != "rhorizon_secret" {
		t.Errorf("data secret TypeName = %q", md.TypeName)
	}

	var sresp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sresp)
	attrs := sresp.Schema.Attributes
	for _, k := range []string{"name", "value", "namespace", "version"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("data secret schema missing attribute %q", k)
		}
	}
	if v, ok := attrs["value"].(dschema.StringAttribute); !ok || !v.Sensitive {
		t.Errorf("data secret.value must be Sensitive")
	}
}

func TestNamespaceDataSource_MetadataAndSchema(t *testing.T) {
	d := newNamespaceDataSource()
	var md datasource.MetadataResponse
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "rhorizon"}, &md)
	if md.TypeName != "rhorizon_namespace" {
		t.Errorf("data namespace TypeName = %q", md.TypeName)
	}

	var sresp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sresp)
	attrs := sresp.Schema.Attributes
	for _, k := range []string{"name"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("data namespace schema missing attribute %q", k)
		}
	}
}

// Provider implements the framework's provider.Provider interface.
// Compile-time check : if a method signature drifts (framework bump
// breaks the contract), this var assignment refuses to compile.
var _ provider.Provider = New("test-compile-check")()
