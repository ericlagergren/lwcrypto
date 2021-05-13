// Package grain implements the Grain128-AEAD cipher.
//
// References:
//
//    [grain]: https://grain-128aead.github.io/
//
package grain

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"runtime"
	"strconv"

	"github.com/ericlagergren/lwcrypto/internal/subtle"
)

var errOpen = errors.New("grain: message authentication failed")

const (
	BlockSize = 16
	KeySize   = 16
	NonceSize = 12
	TagSize   = 8
)

// state is the pure Go "generic" implementation of
// Grain-128AEAD.
//
// Grain-128AEAD has two primary parts:
//
//    1. pre-output generator
//    2. authenticator generator
//
// The pre-output generator has three parts:
//
//    1. an LFSR
//    2. a non-linear FSR (NFSR)
//    3. a pre-output function
//
// The authenticator generator has two parts:
//
//    1. a shift register
//    2. an accumulator
//
// The pre-output generator is defined as
//
//    y_t = h(x) + s_93^t + \sum_{j \in A} b_j^t
//
// where
//
//    A = {2, 15, 36, 45, 64, 73, 89}
//
type state struct {
	// key is the 128-bit key.
	key [4]uint32
	// lfsr is a 128-bit linear feedback shift register.
	//
	// The LFSR is defined as the following polynomial over GF(2)
	//
	//    f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128
	//
	// and updated with
	//
	//    s_127^(t+1) = s_0^t + s_7^t + s_38^t
	//                + s_70^t + s_81^t + s_96^t
	//                = L(S_t)
	lfsr [1040]uint32
	// nfsr is a 128-bit non-linear feedback shift register.
	//
	// nfsr is defined as the following polynomial over GF(2)
	//
	//    g(x) = 1 + x^32 + x^37 + x^72 + x^102 + x^128
	//         + x^44*x^60 + x^61*x^125 + x^63*x^67
	//         + x^69*x^101 + x^80*x^88 + x^110*x^111
	//         + x^115*x^117 + x^46*x^50*x^58
	//         + x^103*x^104*x^106 + x^33*x^35*x^36*x^40
	//
	// and updated with
	//
	//    b_126^(t+1) = s_0^t + b_0^t + b_26^t + b_56^t
	//                + b_91^t + b_96^t + b_3^t*b_67^t
	//                + b_11^t*b_13^t + b_17^t*b_18^t
	//                + b_27^t*b_59^t + b_40^t*b_48^t
	//                + b_61^t*b_65^t + b_68^t*b_84^t
	//                + b_22^t*b_24^t*b_25^t
	//                + b_70^t*b_78^t*b_82^t
	//                + b_88^t*b_92^t*b_93^t*b_95^t
	//                = s_0^t + F(B_t)
	nfsr [1040]uint32
	// i is the index into lfsr and nfsr.
	i int
	// count is the number of words in lfsr and nfsr.
	//
	// Invariant: count = i-4.
	count int
	// acc is the accumulator half of the authentication
	// generator.
	//
	// Specifically, acc is the authentication tag.
	//
	//    A_i = [a_0^i, a_1^i, ..., a_63^i]
	acc uint64
	// reg is the shift register half of the authentication
	// generaetor, containing the most recent 64 odd bits from
	// the pre-output.
	//
	//    R_i = [r_0^i, r_1^i, ..., r_63^i]
	reg uint64
	wtf [16]uint32
}

var _ cipher.AEAD = (*state)(nil)

// New creates a 128-bit Grain128-AEAD AEAD.
//
// Grain128-AEAD must not be used to encrypt more than 2^80 bits
// per key, nonce pair, including additional authenticated data.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("grain: bad key length")
	}
	var s state
	s.setKey(key)
	return &s, nil
}

func (s *state) NonceSize() int {
	return NonceSize
}

func (s *state) Overhead() int {
	return TagSize
}

func (s *state) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("grain: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	s.init(nonce)

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize)
	if subtle.InexactOverlap(out, plaintext) {
		panic("grain: invalid buffer overlap")
	}

	s.encrypt(out[:len(out)-TagSize], plaintext, additionalData)

	s.tag(out[len(out)-TagSize:])

	return ret
}

func (s *state) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("grain: incorrect nonce length: " + strconv.Itoa(len(nonce)))
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}
	s.init(nonce)

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("grain: invalid buffer overlap")
	}

	s.decrypt(out, ciphertext, additionalData)

	expectedTag := make([]byte, TagSize)
	s.tag(expectedTag)

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		runtime.KeepAlive(out)
		return nil, errOpen
	}
	return ret, nil
}

func (s *state) encrypt(dst, src, ad []byte) {
	ad = encodeDER(ad)

	for len(ad) >= 2 {
		v := binary.LittleEndian.Uint16(ad)
		accumulate(s, getmb(next(s)), v)
		ad = ad[2:]
	}

	if len(ad) > 0 {
		word := next(s)
		s.accumulate8(uint8(getmb(word)), ad[0])
		if len(src) > 0 {
			dst[0] = uint8(getkb(word)>>8) ^ src[0]
			s.accumulate8(uint8(getmb(word)>>8), src[0])
			src = src[1:]
			dst = dst[1:]
		}
	}

	for len(src) >= 2 {
		next := next(s)
		v := binary.LittleEndian.Uint16(src)
		binary.LittleEndian.PutUint16(dst, getkb(next)^v)
		accumulate(s, getmb(next), v)
		src = src[2:]
		dst = dst[2:]
	}

	if len(src) > 0 {
		word := next(s)
		dst[0] = byte(getkb(word)) ^ src[0]
		accumulate(s, getmb(word), 0x0100|uint16(src[0]))
		dst = dst[1:]
	} else {
		accumulate(s, getmb(next(s)), 0x01)
	}
}

func (s *state) decrypt(dst, src, ad []byte) {
	ad = encodeDER(ad)

	for len(ad) >= 2 {
		v := binary.LittleEndian.Uint16(ad)
		accumulate(s, getmb(next(s)), v)
		ad = ad[2:]
	}

	if len(ad) > 0 {
		word := next(s)
		s.accumulate8(uint8(getmb(word)), ad[0])
		if len(src) > 0 {
			dst[0] = uint8(getkb(word)>>8) ^ src[0]
			s.accumulate8(uint8(getmb(word)>>8), dst[0])
			src = src[1:]
			dst = dst[1:]
		}
	}

	for len(src) >= 2 {
		next := next(s)
		v := getkb(next) ^ binary.LittleEndian.Uint16(src)
		binary.LittleEndian.PutUint16(dst, v)
		accumulate(s, getmb(next), v)
		src = src[2:]
		dst = dst[2:]
	}

	if len(src) > 0 {
		word := next(s)
		dst[0] = byte(getkb(word)) ^ src[0]
		accumulate(s, getmb(word), 0x0100|uint16(dst[0]))
		dst = dst[1:]
	} else {
		accumulate(s, getmb(next(s)), 0x01)
	}
}

func (s *state) tag(dst []byte) {
	binary.LittleEndian.PutUint64(dst, s.acc)
}

func (s *state) setKey(key []byte) {
	s.key[0] = binary.LittleEndian.Uint32(key[0:4])
	s.key[1] = binary.LittleEndian.Uint32(key[4:8])
	s.key[2] = binary.LittleEndian.Uint32(key[8:12])
	s.key[3] = binary.LittleEndian.Uint32(key[12:16])

	s.nfsr[0] = s.key[0]
	s.nfsr[1] = s.key[1]
	s.nfsr[2] = s.key[2]
	s.nfsr[3] = s.key[3]
}

func (s *state) init(nonce []byte) {
	s.lfsr[0] = binary.LittleEndian.Uint32(nonce[0:4])
	s.lfsr[1] = binary.LittleEndian.Uint32(nonce[4:8])
	s.lfsr[2] = binary.LittleEndian.Uint32(nonce[8:12])
	s.lfsr[3] = 1<<31 - 1

	s.count = 4
	s.i = 0

	for i := 0; i < 8; i++ {
		ks := next(s)
		s.nfsr[i+4] ^= ks
		s.lfsr[i+4] ^= ks
	}

	s.acc = 0
	for i := 0; i < 2; i++ {
		ks := next(s)
		s.acc |= uint64(ks) << (32 * i)
		s.lfsr[i+12] ^= s.key[i]
	}

	s.reg = 0
	for i := 0; i < 2; i++ {
		ks := next(s)
		s.reg |= uint64(ks) << (32 * i)
		s.lfsr[i+14] ^= s.key[i+2]
	}
}

func (s *state) reinit() {
	s.lfsr[3] = s.lfsr[s.i+3]
	s.lfsr[2] = s.lfsr[s.i+2]
	s.lfsr[1] = s.lfsr[s.i+1]
	s.lfsr[0] = s.lfsr[s.i+0]

	s.nfsr[3] = s.nfsr[s.i+3]
	s.nfsr[2] = s.nfsr[s.i+2]
	s.nfsr[1] = s.nfsr[s.i+1]
	s.nfsr[0] = s.nfsr[s.i+0]

	s.i = 0
	s.count = 4
}

func nextGeneric(s *state) uint32 {
	ln0 := uint64(s.lfsr[s.i+1])<<32 | uint64(s.lfsr[s.i])   // 0|1
	ln1 := uint64(s.lfsr[s.i+2])<<32 | uint64(s.lfsr[s.i+1]) // 1|2
	ln2 := uint64(s.lfsr[s.i+3])<<32 | uint64(s.lfsr[s.i+2]) // 2|3
	ln3 := uint64(s.lfsr[s.i+3])                             // 3

	nn0 := uint64(s.nfsr[s.i+1])<<32 | uint64(s.nfsr[s.i])
	nn1 := uint64(s.nfsr[s.i+2])<<32 | uint64(s.nfsr[s.i+1])
	nn2 := uint64(s.nfsr[s.i+3])<<32 | uint64(s.nfsr[s.i+2])
	nn3 := uint64(s.nfsr[s.i+3])

	v := ln0 ^ ln3
	v ^= (ln1 ^ ln2) >> 6
	v ^= ln0 >> 7
	v ^= ln2 >> 17
	s.lfsr[s.count] = uint32(v)

	u := ln0                                                   // s_0
	u ^= nn0                                                   // b_0
	u ^= nn0 >> 26                                             // b_26
	u ^= nn3                                                   // b_93
	u ^= nn1 >> 24                                             // b_56
	u ^= ((nn0 & nn1) ^ nn2) >> 27                             // b_91 + b_27b_59
	u ^= (nn0 & nn2) >> 3                                      // b_3b_67
	u ^= (nn0 >> 11) & (nn0 >> 13)                             // b_11b_13
	u ^= (nn0 >> 17) & (nn0 >> 18)                             // b_17b_18
	u ^= (nn1 >> 8) & (nn1 >> 16)                              // b_40b_48
	u ^= (nn1 >> 29) & (nn2 >> 1)                              // b_61b_65
	u ^= (nn2 >> 4) & (nn2 >> 20)                              // b_68b_84
	u ^= (nn2 >> 24) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31) // b_88b_92b_93b_95
	u ^= (nn0 >> 22) & (nn0 >> 24) & (nn0 >> 25)               // b_22b_24b_25
	u ^= (nn2 >> 6) & (nn2 >> 14) & (nn2 >> 18)                // b_70b_78b_82
	s.nfsr[s.count] = uint32(u)

	s.count++
	s.i++

	if s.count >= len(s.lfsr) {
		s.reinit()
	}

	x := nn0 >> 2
	x ^= nn0 >> 15
	x ^= nn1 >> 4
	x ^= nn1 >> 13
	x ^= nn2
	x ^= nn2 >> 9
	x ^= nn2 >> 25
	x ^= ln2 >> 29
	x ^= (nn0 >> 12) & (ln0 >> 8)
	x ^= (ln0 >> 13) & (ln0 >> 20)
	x ^= (nn2 >> 31) & (ln1 >> 10)
	x ^= (ln1 >> 28) & (ln2 >> 15)
	x ^= (nn0 >> 12) & (nn2 >> 31) & (ln2 >> 30)
	return uint32(x)
}

func accumulateGeneric(s *state, ms, pt uint16) {
	var acctmp uint16
	regtmp := uint32(ms) << 16

	for i := 0; i < 16; i++ {
		var mask uint64 // 0x00
		var rem uint32  // 0x00
		if pt&0x1 != 0 {
			mask = ^uint64(0)
			rem = 0xffff
		}
		s.acc ^= s.reg & mask
		s.reg >>= 1

		acctmp ^= uint16(regtmp & rem)
		s.wtf[i] = regtmp & rem
		regtmp >>= 1

		pt >>= 1
	}

	s.reg |= uint64(ms) << 48
	s.acc ^= uint64(acctmp) << 48
}

func (s *state) accumulate8(ms, pt uint8) {
	mstmp := ms
	var acctmp uint8
	regtmp := uint16(ms) << 8

	for i := 0; i < 8; i++ {
		var mask uint64 // = 0x00
		var rem uint32  // = 0x00
		if pt&0x1 != 0 {
			mask = ^uint64(0)
			rem = 0xff
		}
		s.acc ^= s.reg & mask
		s.reg >>= 1

		acctmp ^= uint8(uint32(regtmp) & rem)
		regtmp >>= 1

		mstmp >>= 1
		pt >>= 1
	}

	s.reg |= uint64(ms) << 56
	s.acc ^= uint64(acctmp) << 56
}

// encodeDER returns DER(len(x)) || x.
func encodeDER(x []byte) []byte {
	if len(x) < 128 {
		return append([]byte{byte(len(x))}, x...)
	}

	t := len(x)
	var n int
	for t != 0 {
		t >>= 8
		n++
	}

	p := make([]byte, n+1)
	p[0] = byte(0x80 | n)

	t = n
	for i := n; i > 0; i-- {
		p[i] = byte(t)
		t >>= 8
	}
	return append(p, x...)
}

func getmb(num uint32) uint16 {
	const (
		mvo0 = 0x22222222
		mvo1 = 0x18181818
		mvo2 = 0x07800780
		mvo3 = 0x007f8000
		mvo4 = 0x80000000
	)

	var t uint32
	// 0xAAA... extracts the odd MAC bits, LSB first.
	x := uint32(num & 0xAAAAAAAA)
	t = x & mvo0
	x = (x ^ t) | (t >> 1)
	t = x & mvo1
	x = (x ^ t) | (t >> 2)
	t = x & mvo2
	x = (x ^ t) | (t >> 4)
	t = x & mvo3
	x = (x ^ t) | (t >> 8)
	t = x & mvo4
	x = (x ^ t) | (t >> 16)
	return uint16(x)
}

func getkb(num uint32) uint16 {
	const (
		mve0 = 0x44444444
		mve1 = 0x30303030
		mve2 = 0x0f000f00
		mve3 = 0x00ff0000
	)

	var t uint32
	// 0x555... extracts the even key bits, LSB first.
	x := uint32(num & 0x55555555)
	t = x & mve0
	x = (x ^ t) | (t >> 1)
	t = x & mve1
	x = (x ^ t) | (t >> 2)
	t = x & mve2
	x = (x ^ t) | (t >> 4)
	t = x & mve3
	x = (x ^ t) | (t >> 8)
	return uint16(x)
}
