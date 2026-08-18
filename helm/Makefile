# Helper targets for the rhorizon Helm chart.
# The chart needs `schema.sql` at its root (referenced via .Files.Get in
# postgres-schema-cm.yaml), this Makefile copies it from the repo root
# so `helm install` / `helm package` work from a clean checkout.

CHART := rhorizon
ROOT  := $(abspath ..)

.PHONY: prepare lint template package clean

prepare:
	cp $(ROOT)/schema.sql $(CHART)/schema.sql

lint: prepare
	helm lint $(CHART)

template: prepare
	helm template test $(CHART)

package: prepare
	helm package $(CHART)

clean:
	rm -f $(CHART)/schema.sql $(CHART)-*.tgz
