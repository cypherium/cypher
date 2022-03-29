package ecc25519

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	PubPriKeySize  = ed25519.PublicKeySize
	FullKeySize    = ed25519.SignatureSize
)

type Curve struct {
	key [FullKeySize]byte
	// the first 32 bytes are the private key, and the last 32 bytes are the public key, but the private key is when it is actually signed
	// the entire key is 64 bytes, so you can't just set the 32-byte private key, you must also set the 32-byte public key.
	// when verifying the signature, only the last 32 bytes of the public key need to be set

	_public, _private [PubPriKeySize]byte
	// the private and public keys used for encryption can be converted by the key used for signature so that a set of keys can be Shared
}

// encrypt up to 64 bytes
func (cr *Curve) Encrypt(plainText []byte) ([]byte, error) {
	var r, R, S, K_B [PubPriKeySize]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	copy(K_B[:], cr._public[:])

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &K_B)
	k_E := sha512.Sum512(S[:])

	srclen := len(plainText)
	if srclen > FullKeySize {
		return nil, errors.New("source data is exceed 64 bytes")
	}
	cipherText := make([]byte, PubPriKeySize+srclen)
	copy(cipherText[:PubPriKeySize], R[:])
	for i := 0; i < srclen; i++ {
		cipherText[PubPriKeySize+i] = plainText[i] ^ k_E[i]
	}

	return cipherText, nil
}

func (cr *Curve) Decrypt(cipherText []byte) ([]byte, error) {
	var R, S, k_B [PubPriKeySize]byte
	if len(cipherText) < PubPriKeySize {
		//return cipherText, errors.New("invalid cipherText or need not Decrypt")
		return cipherText, nil
	}
	copy(R[:], cipherText[:PubPriKeySize])
	copy(k_B[:], cr._private[:])

	curve25519.ScalarMult(&S, &k_B, &R)

	k_E := sha512.Sum512(S[:])
	plainText := make([]byte, len(cipherText)-PubPriKeySize)
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[PubPriKeySize+i] ^ k_E[i]
	}
	return plainText, nil
}
