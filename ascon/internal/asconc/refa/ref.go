// Package ref implements a wrapper around the reference
// implementation of ASCON.
//
// Version used: https://github.com/ascon/ascon-c/tree/a664d3bb2dfa092d550025c440730c56c198e326/crypto_aead/ascon128av12
package ref

/*
#include "ascon.h"
#include "api.h"
#include "crypto_aead.h"
*/
import "C"

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/ericlagergren/lwcrypto/internal/subtle"
)

type aead struct {
	key []byte
}

func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case C.CRYPTO_KEYBYTES:
		return &aead{key: key}, nil
	default:
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}
}

func (a *aead) NonceSize() int {
	return C.CRYPTO_NPUBBYTES
}

func (a *aead) Overhead() int {
	return C.CRYPTO_ABYTES
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, out := subtle.SliceForAppend(dst, len(plaintext)+C.CRYPTO_ABYTES)
	if subtle.InexactOverlap(out, plaintext) {
		panic("ascon: invalid buffer overlap")
	}
	var m *C.uchar
	if len(plaintext) > 0 {
		m = (*C.uchar)(&plaintext[0])
	}
	var ad *C.uchar
	if len(additionalData) > 0 {
		ad = (*C.uchar)(&additionalData[0])
	}
	clen := C.ulonglong(len(out))
	r := C.crypto_aead_encrypt_a(
		(*C.uchar)(&out[0]),
		&clen,
		m,
		C.ulonglong(len(plaintext)),
		ad,
		C.ulonglong(len(additionalData)),
		nil,
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&a.key[0]),
	)
	if r != 0 {
		panic("crypto_aead_encrypt")
	}
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	ret, out := subtle.SliceForAppend(dst, len(ciphertext)-C.CRYPTO_ABYTES)
	if subtle.InexactOverlap(out, ciphertext) {
		panic("ascon: invalid buffer overlap")
	}
	if len(ciphertext) < C.CRYPTO_ABYTES {
		return nil, errors.New("ciphertext too short")
	}
	var ad *C.uchar
	if len(additionalData) > 0 {
		ad = (*C.uchar)(&additionalData[0])
	}
	mlen := C.ulonglong(len(out))
	r := C.crypto_aead_decrypt_a(
		(*C.uchar)(&out[0]),
		&mlen,
		nil,
		(*C.uchar)(&ciphertext[0]),
		C.ulonglong(len(ciphertext)),
		ad,
		C.ulonglong(len(additionalData)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&a.key[0]),
	)
	if r != 0 {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("auth failed")
	}
	return ret, nil
}
