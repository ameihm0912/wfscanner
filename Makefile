TARGETS = wfs
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:
	$(GO) get code.google.com/p/gcfg
	$(GO) get code.google.com/p/go.crypto/openpgp
	$(GO) get camlistore.org/pkg/misc/gpgagent
	$(GO) get camlistore.org/pkg/misc/pinentry

wfs:
	$(GO) install wfs

clean:
	rm -f bin/wfs
	rm -rf pkg/*
