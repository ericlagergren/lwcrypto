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
	"math/bits"
	"strconv"

	"github.com/ericlagergren/lwcrypto/internal/subtle"
)

var errOpen = errors.New("ascon: message authentication failed")

// New128 creates a 128-bit ASCON-128 AEAD.
//
// ASCON-128 provides lower throughput but increased robustness
// compared to ASCON-128a. In particular, ASCON-128 is protected
// against forgeries and key recovery attacks with a complexity
// of 2^96.
//
// Each unique key can encrypt a maximum 2^68 bytes (i.e., 2^64
// plaintext and associated data blocks). Nonces must never be
// reused with the same key. Violating either of these
// constraints compromises the security of the algorithm.
//
// There are no other constraints on the composition of the
// nonce. For example, the nonce can be a counter.
//
// Refer to ASCON's documentation for more information.
func New128(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("ascon: bad key length")
	}
	return &ascon{
		k0: binary.BigEndian.Uint64(key[0:8]),
		k1: binary.BigEndian.Uint64(key[8:16]),
		iv: iv128,
	}, nil
}

// New128a creates a 128-bit ASCON-128a AEAD.
//
// ASCON-128a provides higher throughput but reduced robustness
// compared to ASCON-128. In particular, ASCON-128a is protected
// against forgeries and key recovery attacks with a complexity
// of 2^128.
//
// Each unique key can encrypt a maximum 2^68 bytes (i.e., 2^64
// plaintext and associated data blocks). Nonces must never be
// reused with the same key. Violating either of these
// constraints compromises the security of the algorithm.
//
// There are no other constraints on the composition of the
// nonce. For example, the nonce can be a counter.
//
// Refer to ASCON's documentation for more information.
func New128a(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("ascon: bad key length")
	}
	return &ascon{
		k0: binary.BigEndian.Uint64(key[0:8]),
		k1: binary.BigEndian.Uint64(key[8:16]),
		iv: iv128a,
	}, nil
}

const (
	// BlockSize128a is the size in bytes of an ASCON-128a block.
	BlockSize128a = 128 / 8
	// BlockSize128 is the size in bytes of an ASCON-128 block.
	BlockSize128 = 64 / 8
	// KeySize is the size in bytes of ASCON-128 and ASCON-128a
	// keys.
	KeySize = 128 / 8
	// NonceSize is the size in bytes of ASCON-128 and ASCON-128a
	// nonces.
	NonceSize = 128 / 8
	// TagSize is the size in bytes of ASCON-128 and ASCON-128a
	// authenticators.
	TagSize = 128 / 8
)

type ascon struct {
	k0, k1 uint64
	iv     uint64
}

var _ cipher.AEAD = (*ascon)(nil)

func (a *ascon) NonceSize() int {
	return NonceSize
}

func (a *ascon) Overhead() int {
	return TagSize
}

func (a *ascon) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	// TODO(eric): ciphertext max length?

	n0 := binary.BigEndian.Uint64(nonce[0:8])
	n1 := binary.BigEndian.Uint64(nonce[8:16])

	var s state
	s.init(a.iv, a.k0, a.k1, n0, n1)

	if a.iv == iv128a {
		s.additionalData128a(additionalData)
	} else {
		s.additionalData128(additionalData)
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize)
	if subtle.InexactOverlap(out, plaintext) {
		panic("ascon: invalid buffer overlap")
	}
	if a.iv == iv128a {
		s.encrypt128a(out[:len(plaintext)], plaintext)
	} else {
		s.encrypt128(out[:len(plaintext)], plaintext)
	}

	if a.iv == iv128a {
		s.finalize128a(a.k0, a.k1)
	} else {
		s.finalize128(a.k0, a.k1)
	}
	s.tag(out[len(out)-TagSize:])

	return ret
}

func (a *ascon) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}
	// TODO(eric): ciphertext max length?

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]

	n0 := binary.BigEndian.Uint64(nonce[0:8])
	n1 := binary.BigEndian.Uint64(nonce[8:16])

	var s state
	s.init(a.iv, a.k0, a.k1, n0, n1)

	if a.iv == iv128a {
		s.additionalData128a(additionalData)
	} else {
		s.additionalData128(additionalData)
	}

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("ascon: invalid buffer overlap")
	}
	if a.iv == iv128a {
		s.decrypt128a(out, ciphertext)
	} else {
		s.decrypt128(out, ciphertext)
	}

	if a.iv == iv128a {
		s.finalize128a(a.k0, a.k1)
	} else {
		s.finalize128(a.k0, a.k1)
	}

	expectedTag := make([]byte, TagSize)
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
	iv128  uint64 = 0x80400c0600000000 // Ascon-128
	iv128a uint64 = 0x80800c0800000000 // Ascon-128a
)

type state struct {
	x0, x1, x2, x3, x4 uint64
}

func (s *state) init(iv, k0, k1, n0, n1 uint64) {
	s.x0 = iv
	s.x1 = k0
	s.x2 = k1
	s.x3 = n0
	s.x4 = n1
	p12(s)
	s.x3 ^= k0
	s.x4 ^= k1
}

func (s *state) finalize128a(k0, k1 uint64) {
	s.x2 ^= k0
	s.x3 ^= k1
	p12(s)
	s.x3 ^= k0
	s.x4 ^= k1
}

func (s *state) additionalData128a(ad []byte) {
	if len(ad) > 0 {
		for len(ad) >= BlockSize128a {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s.x1 ^= binary.BigEndian.Uint64(ad[8:16])
			p8(s)
			ad = ad[BlockSize128a:]
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

func (s *state) encrypt128a(dst, src []byte) {
	for len(src) >= BlockSize128a {
		s.x0 ^= binary.BigEndian.Uint64(src[0:8])
		s.x1 ^= binary.BigEndian.Uint64(src[8:16])
		binary.BigEndian.PutUint64(dst[0:8], s.x0)
		binary.BigEndian.PutUint64(dst[8:16], s.x1)
		p8(s)
		src = src[BlockSize128a:]
		dst = dst[BlockSize128a:]
	}
	if len(src) >= 8 {
		s.x0 ^= binary.BigEndian.Uint64(src[0:8])
		s.x1 ^= be64n(src[8:])
		s.x1 ^= pad(len(src) - 8)
		binary.BigEndian.PutUint64(dst[0:8], s.x0)
		put64n(dst[8:], s.x1)
	} else {
		s.x0 ^= be64n(src)
		put64n(dst, s.x0)
		s.x0 ^= pad(len(src))
	}
}

func (s *state) decrypt128a(dst, src []byte) {
	for len(src) >= BlockSize128a {
		c0 := binary.BigEndian.Uint64(src[0:8])
		c1 := binary.BigEndian.Uint64(src[8:16])
		binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
		binary.BigEndian.PutUint64(dst[8:16], s.x1^c1)
		s.x0 = c0
		s.x1 = c1
		p8(s)
		src = src[BlockSize128a:]
		dst = dst[BlockSize128a:]
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

func (s *state) finalize128(k0, k1 uint64) {
	s.x1 ^= k0
	s.x2 ^= k1
	p12(s)
	s.x3 ^= k0
	s.x4 ^= k1
}

func (s *state) additionalData128(ad []byte) {
	if len(ad) > 0 {
		for len(ad) >= BlockSize128 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			p6(s)
			ad = ad[BlockSize128:]
		}
		s.x0 ^= be64n(ad)
		s.x0 ^= pad(len(ad))
		p6(s)
	}
	s.x4 ^= 1
}

func (s *state) encrypt128(dst, src []byte) {
	for len(src) >= BlockSize128 {
		s.x0 ^= binary.BigEndian.Uint64(src[0:8])
		binary.BigEndian.PutUint64(dst[0:8], s.x0)
		p6(s)
		src = src[BlockSize128:]
		dst = dst[BlockSize128:]
	}
	s.x0 ^= be64n(src)
	put64n(dst, s.x0)
	s.x0 ^= pad(len(src))
}

func (s *state) decrypt128(dst, src []byte) {
	for len(src) >= BlockSize128 {
		c := binary.BigEndian.Uint64(src[0:8])
		binary.BigEndian.PutUint64(dst[0:8], s.x0^c)
		s.x0 = c
		p6(s)
		src = src[BlockSize128:]
		dst = dst[BlockSize128:]
	}
	c := be64n(src)
	put64n(dst, s.x0^c)
	s.x0 = mask(s.x0, len(src))
	s.x0 |= c
	s.x0 ^= pad(len(src))
}

func (s *state) tag(dst []byte) {
	binary.BigEndian.PutUint64(dst[0:8], s.x3)
	binary.BigEndian.PutUint64(dst[8:16], s.x4)
}

func pad(n int) uint64 {
	return 0x80 << (56 - 8*n)
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
		x &^= 255 << (56 - 8*i)
	}
	return x
}
