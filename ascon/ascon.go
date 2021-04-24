// Package ascon implements the ASCON AEAD cipher.
//
// References:
//
//    [ascon]: https://ascon.iaik.tugraz.at
//
package ascon

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strconv"

	"github.com/ericlagergren/lwcrypto/internal/subtle"
)

var errOpen = errors.New("ascon: message authentication failed")

// New128a creates a 128-bit ASCON-128a AEAD.
func New128a(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}
	return &ascon{
		k0: binary.BigEndian.Uint64(key[0:8]),
		k1: binary.BigEndian.Uint64(key[8:16]),
	}, nil
}

const (
	// BlockSize is the ASCON-128a block size in bytes.
	BlockSize = 128 / 8

	keySize   = 128 / 8
	nonceSize = 128 / 8
	tagSize   = 128 / 8
)

type ascon struct {
	k0, k1 uint64
}

var _ cipher.AEAD = (*ascon)(nil)

func (a *ascon) NonceSize() int {
	return nonceSize
}

func (a *ascon) Overhead() int {
	return tagSize
}

func (a *ascon) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != nonceSize {
		panic("ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	// TODO(eric): ciphertext max length

	n0 := binary.BigEndian.Uint64(nonce[0:8])
	n1 := binary.BigEndian.Uint64(nonce[8:16])

	var s state
	s.init(a.k0, a.k1, n0, n1)
	s.additionalData(additionalData)

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+tagSize)
	if subtle.InexactOverlap(out, plaintext) {
		panic("ascon: invalid buffer overlap")
	}
	s.encrypt(out[:len(plaintext)], plaintext)

	s.finalize(a.k0, a.k1)
	s.tag(out[len(out)-tagSize:])

	return ret
}

func (a *ascon) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		panic("ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	if len(ciphertext) < tagSize {
		return nil, errOpen
	}
	// TODO(eric): ciphertext max length

	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-tagSize]

	n0 := binary.BigEndian.Uint64(nonce[0:8])
	n1 := binary.BigEndian.Uint64(nonce[8:16])

	var s state
	s.init(a.k0, a.k1, n0, n1)
	s.additionalData(additionalData)

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("ascon: invalid buffer overlap")
	}
	s.decrypt(out, ciphertext)

	s.finalize(a.k0, a.k1)

	expectedTag := make([]byte, tagSize)
	s.tag(expectedTag)

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

const (
	iv128a uint64 = 0x80800c0800000000 // Ascon-128a
)

type state struct {
	x0, x1, x2, x3, x4 uint64
}

func (s *state) init(k0, k1, n0, n1 uint64) {
	s.x0 = iv128a
	s.x1 = k0
	s.x2 = k1
	s.x3 = n0
	s.x4 = n1
	p12(s)
	s.x3 ^= k0
	s.x4 ^= k1
}

func (s *state) finalize(k0, k1 uint64) {
	s.x2 ^= k0
	s.x3 ^= k1
	p12(s)
	s.x3 ^= k0
	s.x4 ^= k1
}

func (s *state) additionalData(ad []byte) {
	if len(ad) > 0 {
		for len(ad) >= BlockSize {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s.x1 ^= binary.BigEndian.Uint64(ad[8:16])
			p8(s)
			ad = ad[BlockSize:]
		}
		if len(ad) >= 8 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s.x1 ^= be64n(ad[8:])
			s.x1 ^= pad(len(ad) - 8)
		} else {
			s.x0 ^= be64n(ad)
			s.x0 ^= pad(len(ad))
		}
		p8(s)
	}
	s.x4 ^= 1
}

func pad(n int) uint64 {
	return 0x80 << (56 - 8*n)
}

func (s *state) encrypt(dst, src []byte) {
	for len(src) >= BlockSize {
		s.x0 ^= binary.BigEndian.Uint64(src[0:8])
		s.x1 ^= binary.BigEndian.Uint64(src[8:16])
		binary.BigEndian.PutUint64(dst[0:8], s.x0)
		binary.BigEndian.PutUint64(dst[8:16], s.x1)
		p8(s)
		src = src[BlockSize:]
		dst = dst[BlockSize:]
	}
	if len(src) >= 8 {
		s.x0 ^= binary.BigEndian.Uint64(src[0:8])
		s.x1 ^= be64n(src[8:])
		s.x1 ^= pad(len(src) - 8)
		binary.BigEndian.PutUint64(dst[0:8], s.x0)
		put64n(dst[8:], s.x1)
	} else {
		s.x0 ^= be64n(src)
		s.x0 ^= pad(len(src))
		put64n(dst, s.x0)
	}
}

func (s *state) decrypt(dst, src []byte) {
	for len(src) >= BlockSize {
		c0 := binary.BigEndian.Uint64(src[0:8])
		c1 := binary.BigEndian.Uint64(src[8:16])
		binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
		binary.BigEndian.PutUint64(dst[8:16], s.x1^c1)
		s.x0 = c0
		s.x1 = c1
		p8(s)
		src = src[BlockSize:]
		dst = dst[BlockSize:]
	}
	if len(src) >= 8 {
		c0 := binary.BigEndian.Uint64(src[0:8])
		c1 := be64n(src[8:])
		binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
		put64n(dst[8:], s.x1^c1)
		s.x0 = c0
		s.x1 = mask(s.x1, len(src)-8)
		s.x1 |= c1
		s.x1 ^= pad(len(src) - 8)
	} else {
		c0 := be64n(src)
		put64n(dst, s.x0^c0)
		s.x0 = mask(s.x0, len(src))
		s.x0 |= c0
		s.x0 ^= pad(len(src))
	}
}

func (s *state) tag(dst []byte) {
	binary.BigEndian.PutUint64(dst[0:8], s.x3)
	binary.BigEndian.PutUint64(dst[8:16], s.x4)
}

func p12Generic(s *state) {
	round(s, 0xf0)
	round(s, 0xe1)
	round(s, 0xd2)
	round(s, 0xc3)
	round(s, 0xb4)
	round(s, 0xa5)
	round(s, 0x96)
	round(s, 0x87)
	round(s, 0x78)
	round(s, 0x69)
	round(s, 0x5a)
	round(s, 0x4b)
}

func p8Generic(s *state) {
	round(s, 0xb4)
	round(s, 0xa5)
	round(s, 0x96)
	round(s, 0x87)
	round(s, 0x78)
	round(s, 0x69)
	round(s, 0x5a)
	round(s, 0x4b)
}

func p6Generic(s *state) {
	round(s, 0x96)
	round(s, 0x87)
	round(s, 0x78)
	round(s, 0x69)
	round(s, 0x5a)
	round(s, 0x4b)
}

func roundGeneric(s *state, C uint64) {
	s0 := s.x0
	s1 := s.x1
	s2 := s.x2
	s3 := s.x3
	s4 := s.x4

	// Round constant
	s2 ^= C

	// Substitution
	s0 ^= s4
	s4 ^= s3
	s2 ^= s1

	// Keccak S-box
	t0 := s0 ^ (^s1 & s2)
	t1 := s1 ^ (^s2 & s3)
	t2 := s2 ^ (^s3 & s4)
	t3 := s3 ^ (^s4 & s0)
	t4 := s4 ^ (^s0 & s1)

	// Substitution
	t1 ^= t0
	t0 ^= t4
	t3 ^= t2
	t2 = ^t2

	// Linear diffusion
	//
	// x0 ← Σ0(x0) = x0 ⊕ (x0 ≫ 19) ⊕ (x0 ≫ 28)
	s.x0 = t0 ^ rotr(t0, 19) ^ rotr(t0, 28)
	// x1 ← Σ1(x1) = x1 ⊕ (x1 ≫ 61) ⊕ (x1 ≫ 39)
	s.x1 = t1 ^ rotr(t1, 61) ^ rotr(t1, 39)
	// x2 ← Σ2(x2) = x2 ⊕ (x2 ≫ 1) ⊕ (x2 ≫ 6)
	s.x2 = t2 ^ rotr(t2, 1) ^ rotr(t2, 6)
	// x3 ← Σ3(x3) = x3 ⊕ (x3 ≫ 10) ⊕ (x3 ≫ 17)
	s.x3 = t3 ^ rotr(t3, 10) ^ rotr(t3, 17)
	// x4 ← Σ4(x4) = x4 ⊕ (x4 ≫ 7) ⊕ (x4 ≫ 41)
	s.x4 = t4 ^ rotr(t4, 7) ^ rotr(t4, 41)
}

func rotr(x uint64, n int) uint64 {
	return bits.RotateLeft64(x, -n)
}

func be64n(b []byte) uint64 {
	var x uint64
	for i := len(b) - 1; i >= 0; i-- {
		x |= uint64(b[i]) << (56 - i*8)
	}
	return x
}

func put64n(b []byte, x uint64) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte(x >> (56 - 8*i))
	}
}

func mask(x uint64, n int) uint64 {
	for i := 0; i < n; i++ {
		x &^= 0xff << (56 - 8*i)
	}
	return x
}
