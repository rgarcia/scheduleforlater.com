SHELL := /bin/bash
PKG := github.com/rgarcia/scheduleforlater.com
SUBPKGS := 
PKGS := $(PKG) $(SUBPKGS)
GODEP := $(GOPATH)/bin/godep
GOLINT := $(GOPATH)/bin/golint

GO_FILES = $(shell find . -type f -name '*.go')

.PHONY: test $(PKGS) build clean

test: $(PKGS)

$(GODEP):
	go get github.com/tools/godep

$(GOLINT):
	go get github.com/golang/lint/golint


Godeps: Godeps/Godeps.json
Godeps/Godeps.json: $(GODEP) $(GO_FILES)
	mkdir -p Godeps
	go get $(PKGS)
	$(GODEP) save -r

build:
	go build $(PKG)

$(PKGS): $(GOLINT)
	gofmt -w=true $(GOPATH)/src/$@/*.go
	$(GOLINT) $(GOPATH)/src/$@/*.go
ifeq ($(COVERAGE),1)
	go test -cover -coverprofile=$(GOPATH)/src/$@/c.out $@ -test.v
	go tool cover -html=$(GOPATH)/src/$@/c.out
else
	go test -v $@
endif

clean:
	rm -rf build release
