# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

GOBIN = ./bin
GO ?= latest
GORUN = env GO111MODULE=on GOPROXY=https://goproxy.io go

all: faucet

faucet:
	$(GORUN) build -o $(GOBIN)/faucet ./src/*.go
	@echo "Done building."
	@echo "Run \"$(GOBIN)/faucet\" to launch faucet."

clean:
	env GO111MODULE=on go clean -cache
	rm -fr $(GOBIN)/*

