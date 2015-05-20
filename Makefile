TARGETS = wfs
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:
	$(GO) get code.google.com/p/gcfg

wfs:
	$(GO) install wfs

clean:
	rm -f bin/wfs
	rm -rf pkg/*
