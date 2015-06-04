TARGETS = wfs wfs2mozdef
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:
	$(GO) get code.google.com/p/gcfg
	$(GO) get code.google.com/p/go.crypto/openpgp
	$(GO) get camlistore.org/pkg/misc/gpgagent
	$(GO) get camlistore.org/pkg/misc/pinentry
	$(GO) get github.com/streadway/amqp
	$(GO) get github.com/ameihm0912/gozdef
	$(GO) get github.com/ameihm0912/govfeed/src/govfeed

wfs:
	$(GO) install wfs

wfs2mozdef:
	$(GO) install wfs2mozdef

clean:
	rm -f bin/wfs
	rm -rf pkg/*
