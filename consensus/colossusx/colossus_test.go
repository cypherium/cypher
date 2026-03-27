package colossusx

import (
	"encoding/hex"
	"testing"
)

func makeLightAndFullInputs(t *testing.T, datasetBytes uint64, epoch uint64) ([]uint32, []uint32) {
	t.Helper()
	seed := seedHash(epoch*epochLength + 1)
	cache := make([]uint32, cacheSize(epoch*epochLength+1)/4)
	generateCache(cache, epoch, seed)
	dataset := make([]uint32, datasetBytes/4)
	generateDataset(dataset, epoch, cache)
	return cache, dataset
}

func TestColossusHashLightFullMatch(t *testing.T) {
	cache, dataset := makeLightAndFullInputs(t, 32*1024, 0)
	sealHash := make([]byte, 32)
	for _, nonce := range []uint64{0, 1, 7, 42, 999} {
		lightDigest, lightResult := colossusHashLight(32*1024, cache, sealHash, nonce)
		fullDigest, fullResult := colossusHashFull(dataset, sealHash, nonce)
		if hex.EncodeToString(lightDigest) != hex.EncodeToString(fullDigest) {
			t.Fatalf("digest mismatch for nonce %d", nonce)
		}
		if hex.EncodeToString(lightResult) != hex.EncodeToString(fullResult) {
			t.Fatalf("result mismatch for nonce %d", nonce)
		}
	}
}

func TestColossusTailTruncationAndPageBoundary(t *testing.T) {
	cache, dataset := makeLightAndFullInputs(t, 32*1024, 0)
	sealHash := []byte("0123456789abcdef0123456789abcdef")
	nonce := uint64(123)

	baseDigest, baseResult := colossusHashFull(dataset, sealHash, nonce)
	withTailDigest, withTailResult := colossusHashFull(append(append([]uint32{}, dataset...), 1, 2, 3), sealHash, nonce)
	if hex.EncodeToString(baseDigest) != hex.EncodeToString(withTailDigest) || hex.EncodeToString(baseResult) != hex.EncodeToString(withTailResult) {
		t.Fatalf("full hash should ignore tail words beyond effective dataset page boundary")
	}

	lightA1, lightB1 := colossusHashLight(32*1024, cache, sealHash, nonce)
	lightA2, lightB2 := colossusHashLight(32*1024+17, cache, sealHash, nonce)
	if hex.EncodeToString(lightA1) != hex.EncodeToString(lightA2) || hex.EncodeToString(lightB1) != hex.EncodeToString(lightB2) {
		t.Fatalf("light hash should ignore tail bytes beyond effective dataset bytes")
	}
}

func TestColossusGoldenVectors(t *testing.T) {
	cache0, dataset0 := makeLightAndFullInputs(t, 32*1024, 0)
	cache1, dataset1 := makeLightAndFullInputs(t, 32*1024, 1)

	// Provenance: vectors are derived from the ColossusHash-v1.1 spec formulas
	// in this package and frozen from a standalone reproduction script.
	// Regenerate with:
	//   GO111MODULE=off go run ./tmp_vec_main.go
	vectors := []struct {
		name       string
		dataset    []uint32
		cache      []uint32
		datasetLen uint64
		sealHash   string
		nonce      uint64
		digestHex  string
		resultHex  string
	}{
		{name: "epoch0_nonce0", dataset: dataset0, cache: cache0, datasetLen: 32 * 1024, sealHash: "0000000000000000000000000000000000000000000000000000000000000000", nonce: 0, digestHex: "563c594018ce5bbed726d57e3cd319db39c5eebfefc467866b499adc8a77f50f", resultHex: "b06d89147224eb6c91d4639e65bed48c10c72b5cff54011c120303ef22ac96a3"},
		{name: "epoch0_nonce7", dataset: dataset0, cache: cache0, datasetLen: 32*1024 + 77, sealHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", nonce: 7, digestHex: "2fa020e77a6110794035cb4b784c3347163dfe75a12ac5930c107dd8f7acbaf5", resultHex: "50f2b9dd66dc31c24dfc178dbe6037c5817f196339b27118237bc4775c08fc3f"},
		{name: "epoch1_nonce42", dataset: dataset1, cache: cache1, datasetLen: 32 * 1024, sealHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nonce: 42, digestHex: "a787b9ec9454d87d4a6e3d293e0df787ab13351c67a3e8002f8dab527c7eba3a", resultHex: "91945711a8c64c05a41a76871929e15326ce279628ca27e1825c99749b715ab4"},
	}

	for _, tc := range vectors {
		sealHash, err := hex.DecodeString(tc.sealHash)
		if err != nil {
			t.Fatalf("decode seal hash: %v", err)
		}
		lightDigest, lightResult := colossusHashLight(tc.datasetLen, tc.cache, sealHash, tc.nonce)
		fullDigest, fullResult := colossusHashFull(tc.dataset, sealHash, tc.nonce)
		if hex.EncodeToString(lightDigest) != hex.EncodeToString(fullDigest) || hex.EncodeToString(lightResult) != hex.EncodeToString(fullResult) {
			t.Fatalf("full/light mismatch for %s", tc.name)
		}
		if got := hex.EncodeToString(fullDigest); got != tc.digestHex {
			t.Fatalf("digest mismatch for %s: got %s", tc.name, got)
		}
		if got := hex.EncodeToString(fullResult); got != tc.resultHex {
			t.Fatalf("result mismatch for %s: got %s", tc.name, got)
		}
	}
}
