// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

// Acceptance tests for rhorizon_secret / rhorizon_namespace resources and
// data sources. Drives the provider through a real plan/apply/refresh
// lifecycle against an in-memory mock vault (httptest.NewServer).
//
// Requires the `terraform` binary in PATH. OpenTofu works too via :
//
//   TF_ACC_TERRAFORM_PATH=/usr/bin/tofu go test ./internal/provider/...
//
// CI ships OpenTofu in the test-go image and exports the env var.

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ---------------------------------------------------------------------------
// In-memory vault stub.
//
// Each test instantiates its own *testVault so there's no cross-test state
// contamination. The stub implements just enough of the vault API surface
// to drive the provider end-to-end : secrets CRUD + namespaces CRUD. No
// auth check, the test always sends the same bearer ; we trust the client
// layer's own auth tests for that path.
// ---------------------------------------------------------------------------

type secretRow struct {
	ID        string
	Name      string
	Namespace string
	Value     string
	Version   int
	IsHoney   bool
}

type namespaceRow struct {
	ID                string
	Name              string
	OwnerGroupID      string
	EnforceMembership bool
	DeleteProtection  string
}

type testVault struct {
	mu sync.Mutex
	// Two-level map : namespace -> name -> row. Empty namespace in the
	// request canonicalised to "default" to match server behaviour.
	secrets    map[string]map[string]*secretRow
	namespaces map[string]*namespaceRow
	idSeq      atomic.Uint64
}

func newTestVault() *testVault {
	return &testVault{
		secrets:    map[string]map[string]*secretRow{},
		namespaces: map[string]*namespaceRow{},
	}
}

func (v *testVault) nextID() string {
	return fmt.Sprintf("uuid-%d", v.idSeq.Add(1))
}

func nsCanon(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}

// router builds the minimum HTTP surface the provider exercises. We
// route on path+method ; the FastAPI surface is more permissive (POST
// /secrets/ accepts an `is_honey` field, query-string namespace selector,
// 409 on ambiguous lookups, etc.), modeled here only where the provider
// actually relies on it.
func (v *testVault) router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/vault/secrets/", v.handleSecrets)
	mux.HandleFunc("/api/v1/vault/namespaces/", v.handleNamespaces)

	return mux
}

func (v *testVault) handleSecrets(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Path after the prefix : "" -> POST collection ; "/name" -> per-secret.
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/vault/secrets/")
	ns := nsCanon(r.URL.Query().Get("namespace"))

	switch {
	case rest == "" && r.Method == http.MethodPost:
		var body struct {
			Name      string `json:"name"`
			Value     string `json:"value"`
			Namespace string `json:"namespace"`
			IsHoney   bool   `json:"is_honey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"detail":"bad json"}`, http.StatusBadRequest)
			return
		}
		bodyNS := nsCanon(body.Namespace)
		if _, ok := v.secrets[bodyNS]; !ok {
			v.secrets[bodyNS] = map[string]*secretRow{}
		}
		if _, exists := v.secrets[bodyNS][body.Name]; exists {
			// FastAPI surface returns 409 on collision ; provider doesn't
			// recover from it but the test must not silently overwrite.
			http.Error(w, `{"detail":"already exists"}`, http.StatusConflict)
			return
		}
		row := &secretRow{
			ID:        v.nextID(),
			Name:      body.Name,
			Namespace: bodyNS,
			Value:     body.Value,
			Version:   1,
			IsHoney:   body.IsHoney,
		}
		v.secrets[bodyNS][body.Name] = row
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      row.ID,
			"name":    row.Name,
			"version": row.Version,
		})
		return

	case rest != "":
		name := rest
		row := v.findSecret(ns, name)
		switch r.Method {
		case http.MethodGet:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"name":      row.Name,
				"namespace": row.Namespace,
				"value":     row.Value,
				"version":   row.Version,
			})
			return
		case http.MethodPut:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"detail":"bad json"}`, http.StatusBadRequest)
				return
			}
			row.Value = body.Value
			row.Version++
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      row.ID,
				"name":    row.Name,
				"version": row.Version,
			})
			return
		case http.MethodDelete:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			delete(v.secrets[row.Namespace], row.Name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	http.Error(w, `{"detail":"not implemented"}`, http.StatusMethodNotAllowed)
}

func (v *testVault) findSecret(ns, name string) *secretRow {
	// If the caller passed an explicit namespace, look only there. Otherwise
	// fall back to "default", matches the provider's default behaviour.
	if m, ok := v.secrets[ns]; ok {
		if row, ok := m[name]; ok {
			return row
		}
	}
	return nil
}

func (v *testVault) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()

	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/vault/namespaces/")

	switch {
	case rest == "" && r.Method == http.MethodPost:
		var body struct {
			Name              string `json:"name"`
			OwnerGroupID      string `json:"owner_group_id"`
			EnforceMembership bool   `json:"enforce_membership"`
			DeleteProtection  string `json:"delete_protection"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"detail":"bad json"}`, http.StatusBadRequest)
			return
		}
		if body.DeleteProtection == "" {
			body.DeleteProtection = "free"
		}
		if _, exists := v.namespaces[body.Name]; exists {
			http.Error(w, `{"detail":"already exists"}`, http.StatusConflict)
			return
		}
		row := &namespaceRow{
			ID:                v.nextID(),
			Name:              body.Name,
			OwnerGroupID:      body.OwnerGroupID,
			EnforceMembership: body.EnforceMembership,
			DeleteProtection:  body.DeleteProtection,
		}
		v.namespaces[body.Name] = row
		writeJSON(w, http.StatusOK, nsResponse(row))
		return

	case rest != "":
		name := rest
		row := v.namespaces[name]
		switch r.Method {
		case http.MethodGet:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, nsResponse(row))
			return
		case http.MethodPut:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			var body struct {
				OwnerGroupID      *string `json:"owner_group_id"`
				EnforceMembership *bool   `json:"enforce_membership"`
				DeleteProtection  *string `json:"delete_protection"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"detail":"bad json"}`, http.StatusBadRequest)
				return
			}
			// Server-side one-way ratchet : refuse relaxing changes so the
			// provider can be tested against the same posture it'd see in
			// prod. The provider should pre-empt this with its own Diags
			// but the back-stop must exist on the wire too.
			if body.EnforceMembership != nil {
				if row.EnforceMembership && !*body.EnforceMembership {
					http.Error(w, `{"detail":"enforce_membership is set-once"}`,
						http.StatusLocked)
					return
				}
				row.EnforceMembership = *body.EnforceMembership
			}
			if body.DeleteProtection != nil {
				rank := map[string]int{"free": 0, "soft": 1, "protected": 2}
				if rank[*body.DeleteProtection] < rank[row.DeleteProtection] {
					http.Error(w, `{"detail":"delete_protection is one-way"}`,
						http.StatusLocked)
					return
				}
				row.DeleteProtection = *body.DeleteProtection
			}
			if body.OwnerGroupID != nil {
				row.OwnerGroupID = *body.OwnerGroupID
			}
			writeJSON(w, http.StatusOK, nsResponse(row))
			return
		case http.MethodDelete:
			if row == nil {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			delete(v.namespaces, name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	http.Error(w, `{"detail":"not implemented"}`, http.StatusMethodNotAllowed)
}

func nsResponse(r *namespaceRow) map[string]any {
	return map[string]any{
		"id":                 r.ID,
		"name":               r.Name,
		"owner_group_id":     r.OwnerGroupID,
		"enforce_membership": r.EnforceMembership,
		"delete_protection":  r.DeleteProtection,
		"archived_at":        nil,
		"created_by":         nil,
		"created_at":         nil,
		"secret_count":       0,
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// Provider factory used by every TestStep. Each call gets a fresh provider
// instance ; the framework wires it up over protocol v6 to the in-process
// terraform/tofu binary.
// ---------------------------------------------------------------------------

func providerFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"rhorizon": providerserver.NewProtocol6WithError(New("acc")()),
	}
}

func providerBlock(addr string) string {
	return fmt.Sprintf(`
provider "rhorizon" {
  address = %q
  token   = "rh_test"
}
`, addr)
}

// ---------------------------------------------------------------------------
// rhorizon_secret resource
// ---------------------------------------------------------------------------

func TestAccSecretResource_CreateReadUpdateDelete(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := func(name, value string) string {
		return providerBlock(srv.URL) + fmt.Sprintf(`
resource "rhorizon_secret" "this" {
  name  = %q
  value = %q
}
`, name, value)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			// Create + first apply.
			{
				Config: cfg("api-key", "v1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_secret.this", "name", "api-key"),
					resource.TestCheckResourceAttr("rhorizon_secret.this", "value", "v1"),
					resource.TestCheckResourceAttr("rhorizon_secret.this", "namespace", "default"),
					resource.TestCheckResourceAttr("rhorizon_secret.this", "version", "1"),
					resource.TestCheckResourceAttr("rhorizon_secret.this", "is_honey", "false"),
					resource.TestCheckResourceAttrSet("rhorizon_secret.this", "id"),
				),
			},
			// Update : same name, new value -> version bump in place.
			{
				Config: cfg("api-key", "v2-longer-payload"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_secret.this", "value", "v2-longer-payload"),
					resource.TestCheckResourceAttr("rhorizon_secret.this", "version", "2"),
				),
			},
		},
	})
}

func TestAccSecretResource_NamespaceForcesReplace(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := func(ns string) string {
		return providerBlock(srv.URL) + fmt.Sprintf(`
resource "rhorizon_secret" "ns_scoped" {
  name      = "db-pass"
  value     = "s3kr3t"
  namespace = %q
}
`, ns)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg("prod"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_secret.ns_scoped", "namespace", "prod"),
					resource.TestCheckResourceAttr("rhorizon_secret.ns_scoped", "version", "1"),
				),
			},
			{
				// Switching namespace must trigger destroy+create (schema
				// declares stringplanmodifier.RequiresReplace). After the
				// replace the version resets to 1 because the row in
				// `staging` was freshly created.
				Config: cfg("staging"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_secret.ns_scoped", "namespace", "staging"),
					resource.TestCheckResourceAttr("rhorizon_secret.ns_scoped", "version", "1"),
				),
			},
		},
	})
}

func TestAccSecretResource_ImportState(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := providerBlock(srv.URL) + `
resource "rhorizon_secret" "imp" {
  name  = "imported"
  value = "v1"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				ResourceName:      "rhorizon_secret.imp",
				ImportState:       true,
				ImportStateId:     "imported",
				ImportStateVerify: true,
				// The GET /secrets/{name} response does not include `id`
				// today, so Read() leaves it blank on import. We tell the
				// framework to use `name` as the identifier and ignore
				// `id` during diff. Follow-up : extend SecretValue + the
				// API to return id so the import flow round-trips
				// cleanly without these overrides.
				ImportStateVerifyIdentifierAttribute: "name",
				// Both `id` and `is_honey` are missing from the GET
				// response shape (SecretValue) so Read() leaves them
				// blank on import. Follow-up : enrich the API response
				// + client struct + Read() so import is lossless.
				ImportStateVerifyIgnore: []string{"id", "is_honey"},
			},
		},
	})
}

func TestAccSecretResource_DriftRecreate(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := providerBlock(srv.URL) + `
resource "rhorizon_secret" "drift" {
  name  = "ghost"
  value = "v1"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				// Simulate out-of-band deletion : the next refresh must
				// notice the resource is gone (Read -> 404 -> RemoveResource)
				// and the plan must re-create it on the same step.
				PreConfig: func() {
					vault.mu.Lock()
					delete(vault.secrets["default"], "ghost")
					vault.mu.Unlock()
				},
				Config:             cfg,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_secret.drift", "value", "v1"),
					resource.TestCheckResourceAttr("rhorizon_secret.drift", "version", "1"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// rhorizon_namespace resource
// ---------------------------------------------------------------------------

func TestAccNamespaceResource_CreateReadDelete(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := providerBlock(srv.URL) + `
resource "rhorizon_namespace" "this" {
  name           = "team-a"
  owner_group_id = "grp-1234"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("rhorizon_namespace.this", "name", "team-a"),
					resource.TestCheckResourceAttr("rhorizon_namespace.this", "owner_group_id", "grp-1234"),
					resource.TestCheckResourceAttr("rhorizon_namespace.this", "enforce_membership", "false"),
					resource.TestCheckResourceAttr("rhorizon_namespace.this", "delete_protection", "free"),
					resource.TestCheckResourceAttrSet("rhorizon_namespace.this", "id"),
				),
			},
		},
	})
}

func TestAccNamespaceResource_OneWayRatchetRelax(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	enforced := providerBlock(srv.URL) + `
resource "rhorizon_namespace" "ratchet" {
  name               = "team-b"
  owner_group_id     = "grp-1234"
  enforce_membership = true
}
`
	relaxed := providerBlock(srv.URL) + `
resource "rhorizon_namespace" "ratchet" {
  name               = "team-b"
  owner_group_id     = "grp-1234"
  enforce_membership = false
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: enforced,
				Check: resource.TestCheckResourceAttr(
					"rhorizon_namespace.ratchet", "enforce_membership", "true"),
			},
			{
				// The provider Update() blocks true -> false at plan time
				// with a typed diagnostic ; the server-side 423 is a
				// back-stop we don't expect to hit here.
				Config:      relaxed,
				ExpectError: regexpMustCompile(`enforce_membership is set-once`),
			},
		},
	})
}

func TestAccNamespaceResource_DeleteProtectionUpgrade(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := func(mode string) string {
		return providerBlock(srv.URL) + fmt.Sprintf(`
resource "rhorizon_namespace" "dp" {
  name              = "team-c"
  owner_group_id    = "grp-1234"
  delete_protection = %q
}
`, mode)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg("free"),
				Check: resource.TestCheckResourceAttr(
					"rhorizon_namespace.dp", "delete_protection", "free"),
			},
			{
				// free -> soft is a valid upgrade.
				Config: cfg("soft"),
				Check: resource.TestCheckResourceAttr(
					"rhorizon_namespace.dp", "delete_protection", "soft"),
			},
			{
				// soft -> protected is also valid.
				Config: cfg("protected"),
				Check: resource.TestCheckResourceAttr(
					"rhorizon_namespace.dp", "delete_protection", "protected"),
			},
			{
				// protected -> soft is a relax, must be blocked at plan time.
				Config:      cfg("soft"),
				ExpectError: regexpMustCompile(`delete_protection is one-way`),
			},
		},
	})
}

func TestAccNamespaceResource_ImportState(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	cfg := providerBlock(srv.URL) + `
resource "rhorizon_namespace" "imp" {
  name           = "team-d"
  owner_group_id = "grp-1234"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				ResourceName:      "rhorizon_namespace.imp",
				ImportState:       true,
				ImportStateId:     "team-d",
				ImportStateVerify: true,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Data sources
// ---------------------------------------------------------------------------

func TestAccSecretDataSource_ReadExisting(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	// Pre-seed a secret out-of-band, data sources read what already exists.
	vault.secrets["default"] = map[string]*secretRow{
		"oob-key": {
			ID:        "uuid-pre",
			Name:      "oob-key",
			Namespace: "default",
			Value:     "minted-by-operator",
			Version:   7,
		},
	}

	cfg := providerBlock(srv.URL) + `
data "rhorizon_secret" "lookup" {
  name = "oob-key"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.rhorizon_secret.lookup", "name", "oob-key"),
					resource.TestCheckResourceAttr("data.rhorizon_secret.lookup", "value", "minted-by-operator"),
					resource.TestCheckResourceAttr("data.rhorizon_secret.lookup", "namespace", "default"),
					resource.TestCheckResourceAttr("data.rhorizon_secret.lookup", "version", "7"),
				),
			},
		},
	})
}

func TestAccNamespaceDataSource_ReadExisting(t *testing.T) {
	vault := newTestVault()
	srv := httptest.NewServer(vault.router())
	defer srv.Close()

	vault.namespaces["team-e"] = &namespaceRow{
		ID:                "uuid-ns-pre",
		Name:              "team-e",
		OwnerGroupID:      "grp-existing",
		EnforceMembership: true,
		DeleteProtection:  "soft",
	}

	cfg := providerBlock(srv.URL) + `
data "rhorizon_namespace" "lookup" {
  name = "team-e"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.rhorizon_namespace.lookup", "name", "team-e"),
					resource.TestCheckResourceAttr("data.rhorizon_namespace.lookup", "owner_group_id", "grp-existing"),
					resource.TestCheckResourceAttr("data.rhorizon_namespace.lookup", "enforce_membership", "true"),
					resource.TestCheckResourceAttr("data.rhorizon_namespace.lookup", "delete_protection", "soft"),
					resource.TestCheckResourceAttr("data.rhorizon_namespace.lookup", "id", "uuid-ns-pre"),
				),
			},
		},
	})
}

// regexpMustCompile is a thin wrapper to keep test config lines readable
// without dragging regexp imports into every TestStep call site.
func regexpMustCompile(s string) *regexp.Regexp {
	return regexp.MustCompile(s)
}
