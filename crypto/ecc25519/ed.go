package ecc25519

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/ed25519"
	"strings"
)

// generate private and public key pairs
func (es *Curve) MakeKey() (err error) {
	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	copy(es.key[:], pri[:])
	var _pri [PubPriKeySize]byte
	var _pub [PubPriKeySize]byte
	copy(_pri[:], pri[:PubPriKeySize])
	copy(_pub[:], pub[:PubPriKeySize])
	PrivateKeyToCurve25519(&es._private, &_pri)
	PublicKeyToCurve25519(&es._public, &_pub)
	return err
}

// if you only need to verify the signature, you only need the public key. Generally, the verifier does not have a private key
//pub32 must be longer than 32 and only the first 32 bytes are fetched
func (es *Curve) SetPublic(pub32 []byte) error {
	if len(pub32) < PubPriKeySize {
		return errors.New("public key length require at least 32 bytes")
	}
	copy(es.key[PubPriKeySize:], pub32[:PubPriKeySize])
	var pub [PubPriKeySize]byte
	copy(pub[:], pub32)
	PublicKeyToCurve25519(&es._public, &pub)
	return nil
}
func (es *Curve) GetPublic() []byte {
	pub := make([]byte, PubPriKeySize)
	copy(pub, es.key[PubPriKeySize:])
	return pub
}
func (es *Curve) SetPublicString(pub string) error {
	p, err := hex.DecodeString(pub)
	if err != nil {
		return err
	}
	return es.SetPublic(p)
}
func (es *Curve) GetPublicString() string {
	return strings.ToUpper(hex.EncodeToString(es.key[PubPriKeySize:]))
}

// if you must set the private key to sign, note that you also need to set the public key, because the real private key is actually a combination of the public key and private key
func (es *Curve) SetPrivate(pri32 []byte) error {
	if len(pri32) < PubPriKeySize {
		return errors.New("private key length require at least 32 bytes")
	}
	copy(es.key[:PubPriKeySize], pri32[:PubPriKeySize])
	var pri [PubPriKeySize]byte
	copy(pri[:], pri32[:PubPriKeySize])
	PrivateKeyToCurve25519(&es._private, &pri)
	return nil
}
func (es *Curve) GetPrivate() []byte {
	pri := make([]byte, PubPriKeySize)
	copy(pri, es.key[:PubPriKeySize])
	return pri
}
func (es *Curve) SetPrivateString(pri string) error {
	p, err := hex.DecodeString(pri)
	if err != nil {
		return err
	}
	return es.SetPrivate(p)
}
func (es *Curve) GetPrivateString() string {
	return strings.ToUpper(hex.EncodeToString(es.key[:PubPriKeySize]))
}
func (es *Curve) GetKey() []byte {
	key := make([]byte, FullKeySize)
	copy(key, es.key[:])
	return key
}
func (es *Curve) SetKey(key []byte) error {
	if len(key) < FullKeySize {
		return errors.New("key length require at least 64 bytes")
	}
	copy(es.key[:], key[:FullKeySize])
	var _pri, _pub [PubPriKeySize]byte
	copy(_pri[:], key[:PubPriKeySize])
	copy(_pub[:], key[PubPriKeySize:])
	PrivateKeyToCurve25519(&es._private, &_pri)
	PublicKeyToCurve25519(&es._public, &_pub)
	return nil
}
func (es *Curve) GetKeyString() string {
	return strings.ToUpper(hex.EncodeToString(es.key[:]))
}
func (es *Curve) SetKeyString(key string) error {
	k, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	return es.SetKey(k)
}
func (es *Curve) Sign(data []byte) []byte {
	var _key []byte
	copy(_key[:], es.key[:FullKeySize])

	sign := ed25519.Sign(_key, data)
	return sign[:FullKeySize]
}
func (es *Curve) Verify(sign *[FullKeySize]byte, data []byte) bool {
	var _pub []byte
	var _sign []byte
	copy(_pub[:], es.key[PubPriKeySize:])
	copy(_sign[:], sign[PubPriKeySize:])
	return ed25519.Verify(_pub, data, _sign)
}
