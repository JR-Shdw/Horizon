# Makefile for the rhorizon docs site (mkdocs-material).
# Avoids requiring a local pip/python install, runs everything in
# the official docker image.

IMG := docker.io/squidfunk/mkdocs-material:latest

.PHONY: serve build clean

# Live preview at http://127.0.0.1:8000
serve:
	docker run --rm -it -p 8000:8000 \
	  -v $$(pwd):/docs -w /docs \
	  $(IMG) serve -a 0.0.0.0:8000

build:
	docker run --rm \
	  -v $$(pwd):/docs -w /docs \
	  $(IMG) build

clean:
	rm -rf site/
