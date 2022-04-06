# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: cypher android ios cypher-cross evm all test clean
.PHONY: cypher-linux cypher-linux-386 cypher-linux-amd64 cypher-linux-mips64 cypher-linux-mips64le
.PHONY: cypher-linux-arm cypher-linux-arm-5 cypher-linux-arm-6 cypher-linux-arm-7 cypher-linux-arm64
.PHONY: cypher-darwin cypher-darwin-386 cypher-darwin-amd64
.PHONY: cypher-windows cypher-windows-386 cypher-windows-amd64

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=off go run

cypher:
	build/env.sh go run build/ci.go install ./cmd/cypher
	@echo "Done building."
	@echo "Run \"$(GOBIN)/cypher\" to launch cypher."

bootnode:
	build/env.sh go run build/ci.go install ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/bootnode\" to launch bootnode."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/cypher.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Geth.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

lint: ## Run linters.
	build/env.sh go run build/ci.go lint

clean:
	env GO111MODULE=on go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

cypher-cross: cypher-linux cypher-darwin cypher-windows cypher-android cypher-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/cypher-*

cypher-linux: cypher-linux-386 cypher-linux-amd64 cypher-linux-arm cypher-linux-mips64 cypher-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-*

cypher-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/cypher
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep 386

cypher-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/cypher
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep amd64

cypher-linux-arm: cypher-linux-arm-5 cypher-linux-arm-6 cypher-linux-arm-7 cypher-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep arm

cypher-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/cypher
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep arm-5

cypher-linux-arm-6:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/cypher
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep arm-6

cypher-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/cypher
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep arm-7

cypher-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/cypher
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep arm64

cypher-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/cypher
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep mips

cypher-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/cypher
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep mipsle

cypher-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/cypher
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep mips64

cypher-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/cypher
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/cypher-linux-* | grep mips64le

cypher-darwin: cypher-darwin-386 cypher-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/cypher-darwin-*

cypher-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/cypher
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-darwin-* | grep 386

cypher-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/cypher
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-darwin-* | grep amd64

cypher-windows: cypher-windows-386 cypher-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/cypher-windows-*

cypher-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/cypher
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-windows-* | grep 386

cypher-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/cypher
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/cypher-windows-* | grep amd64
