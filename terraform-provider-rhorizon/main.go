// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

// terraform-provider-rhorizon, manages secrets, namespaces, and groups
// in a Resurgamus Horizon vault as Terraform resources.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/JR-Shdw/Horizon/terraform-provider-rhorizon/internal/provider"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/shdw/rhorizon",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}

// version is set via -ldflags at build time. Defaults to "dev" for
// uncommitted local builds.
var version = "dev"
