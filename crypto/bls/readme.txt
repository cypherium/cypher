bls library from: https://github.com/herumi/bls

test:
 go test -tags bn256 .
 go test -tags bn384 .
 go test -tags bn384_256 .