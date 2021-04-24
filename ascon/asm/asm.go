package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../ascon.s -stubs ../stub.go -pkg ascon

func main() {
	Package("github.com/ericlagergren/lwcrypto/ascon")
	ConstraintExpr("amd64,gc,!purego")

	declarePermute()
	declareRound()

	Generate()
}

func declarePermute() {
	for _, v := range []struct {
		name string
		rc   []int
	}{
		{"p12", p12},
		{"p8", p8},
		{"p6", p6},
	} {
		TEXT(v.name, NOSPLIT, "func(s *state)")
		Pragma("noescape")
		p := Load(Param("s"), GP64())
		s := loadState(p)
		permute(v.rc, s)
		storeState(s, p)
		RET()
	}
}

func declareRound() {
	TEXT("round", NOSPLIT, "func(s *state, C uint64)")
	Pragma("noescape")

	p := Load(Param("s"), GP64())
	s := loadState(p)
	C := Load(Param("C"), GP64())
	round(s, C)
	storeState(s, p)
	RET()
}

func loadState(p Register) state {
	s := state{
		x0: GP64(),
		x1: GP64(),
		x2: GP64(),
		x3: GP64(),
		x4: GP64(),
	}
	MOVQ(Mem{Base: p, Disp: 0}, s.x0)
	MOVQ(Mem{Base: p, Disp: 8}, s.x1)
	MOVQ(Mem{Base: p, Disp: 16}, s.x2)
	MOVQ(Mem{Base: p, Disp: 24}, s.x3)
	MOVQ(Mem{Base: p, Disp: 32}, s.x4)
	return s
}

func storeState(s state, p Register) {
	MOVQ(s.x0, Mem{Base: p, Disp: 0})
	MOVQ(s.x1, Mem{Base: p, Disp: 8})
	MOVQ(s.x2, Mem{Base: p, Disp: 16})
	MOVQ(s.x3, Mem{Base: p, Disp: 24})
	MOVQ(s.x4, Mem{Base: p, Disp: 32})
}

var (
	p12 = []int{
		0xf0, 0xe1, 0xd2, 0xc3,
		0xb4, 0xa5, 0x96, 0x87,
		0x78, 0x69, 0x5a, 0x4b,
	}
	p8 = []int{
		0xb4, 0xa5, 0x96, 0x87,
		0x78, 0x69, 0x5a, 0x4b,
	}
	p6 = []int{0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
)

func permute(rc []int, s state) {
	for i, C := range rc {
		Commentf("Start round %d", i+1)
		round(s, C)
		Commentf("End round %d\n", i+1)
	}
}

func round(s state, C interface{}) {
	switch t := C.(type) {
	case Register:
		// OK
	case int:
		C = Imm(uint64(t))
	default:
		panic(fmt.Sprintf("unknown type: %T", C))
	}

	Comment("Round constant")
	XORQ(C.(Op), s.x2)

	Comment("Substitution")
	XORQ(s.x4, s.x0) // s.x0 ^= s.x4
	XORQ(s.x3, s.x4) // s.x4 ^= s.x3
	XORQ(s.x1, s.x2) // s.x2 ^= s.x1

	Comment("Keccak S-box")
	var t state
	t.x0 = sbox(GP64(), s.x0, s.x1, s.x2)
	t.x1 = sbox(GP64(), s.x1, s.x2, s.x3)
	t.x2 = sbox(GP64(), s.x2, s.x3, s.x4)
	t.x3 = sbox(GP64(), s.x3, s.x4, s.x0)
	t.x4 = sbox(GP64(), s.x4, s.x0, s.x1)

	Comment("Substituton")
	XORQ(t.x0, t.x1) // t.x1 ^= t.x0
	XORQ(t.x4, t.x0) // t.x0 ^= t.x4
	XORQ(t.x2, t.x3) // t.x3 ^= t.x2
	NOTQ(t.x2)       // t.x2 = ^t.x2

	Comment("Linear diffusion")
	ldiff(s.x0, t.x0, 19, 28)
	ldiff(s.x1, t.x1, 61, 39)
	ldiff(s.x2, t.x2, 1, 6)
	ldiff(s.x3, t.x3, 10, 17)
	ldiff(s.x4, t.x4, 7, 41)
}

// sbox sets z = a ^ (^b & c) and returns z.
func sbox(z, a, b, c GPVirtual) GPVirtual {
	nb := GP64()
	MOVQ(b, nb)
	NOTQ(nb)    // b = ^b
	MOVQ(c, z)  // z = c
	ANDQ(nb, z) // z = ^b & c
	XORQ(a, z)  // z = a ^ z
	return z
}

// ldiff sets z = x ^ rotr(x, n0) ^ rotr(x, n1).
func ldiff(z, x GPVirtual, n0, n1 uint64) {
	// z = rotr(x, n0)
	MOVQ(x, z)
	RORQ(Imm(n0), z)

	// z = x ^ z
	XORQ(x, z)

	// t = rotr(x, n0)
	t := GP64()
	MOVQ(x, t)
	RORQ(Imm(n1), t)

	XORQ(t, z) // z = z ^ t
}

type state struct {
	x0, x1, x2, x3, x4 GPVirtual
}
