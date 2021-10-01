package main

import (
	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/ir"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../ascon_amd64.s -stubs ../stub_amd64.go -pkg ascon

func main() {
	Package("github.com/ericlagergren/lwcrypto/ascon")
	ConstraintExpr("gc,!purego")

	declarePermute()
	declareRound()
	declareAdditionalData128a()
	declareEncryptBlocks128a()
	declareDecryptBlocks128a()

	Generate()
}

func declareAdditionalData128a() {
	TEXT("additionalData128a", NOSPLIT, "func(s *state, ad []byte)")
	Pragma("noescape")
	Instruction(&ir.Instruction{
		Opcode:   "JMP",
		Operands: []Op{LabelRef("·additionalData128aGeneric(SB)")},
	})
	RET()
}

func declareEncryptBlocks128a() {
	TEXT("encryptBlocks128a", NOSPLIT, "func(s *state, dst, src []byte)")
	Pragma("noescape")
	Instruction(&ir.Instruction{
		Opcode:   "JMP",
		Operands: []Op{LabelRef("·encryptBlocks128aGeneric(SB)")},
	})
	RET()
}

func declareDecryptBlocks128a() {
	TEXT("decryptBlocks128a", NOSPLIT, "func(s *state, dst, src []byte)")
	Pragma("noescape")
	Instruction(&ir.Instruction{
		Opcode:   "JMP",
		Operands: []Op{LabelRef("·decryptBlocks128aGeneric(SB)")},
	})
	RET()
}

func declarePermute() {
	for _, v := range []struct {
		name string
		rc   []uint32
	}{
		{"p12", p12},
		{"p8", p8},
		{"p6", p6},
	} {
		TEXT(v.name, NOSPLIT, "func(s *state)")
		Pragma("noescape")
		p := Load(Param("s"), GP64())
		s := loadState(Mem{Base: p})
		permute(v.rc, s)
		storeState(s, Mem{Base: p})
		RET()
	}
}

func declareRound() {
	TEXT("round", NOSPLIT, "func(s *state, C uint64)")
	Pragma("noescape")

	p := Load(Param("s"), GP64())
	s := loadState(Mem{Base: p})
	C := Load(Param("C"), GP64())
	round(s, C)
	storeState(s, Mem{Base: p})
	RET()
}

func loadState(m Mem) state {
	s := state{
		0: GP64(),
		1: GP64(),
		2: GP64(),
		3: GP64(),
		4: GP64(),
	}
	for i, r := range s {
		MOVQ(m.Offset(i*8), r)
	}
	return s
}

func storeState(s state, m Mem) {
	for i, r := range s {
		MOVQ(r, m.Offset(i*8))
	}
}

var (
	p12 = []uint32{
		0xf0, 0xe1, 0xd2, 0xc3,
		0xb4, 0xa5, 0x96, 0x87,
		0x78, 0x69, 0x5a, 0x4b,
	}
	p8 = []uint32{
		0xb4, 0xa5, 0x96, 0x87,
		0x78, 0x69, 0x5a, 0x4b,
	}
	p6 = []uint32{0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
)

func permute(rc []uint32, s state) {
	for i, C := range rc {
		Commentf("Start round %d", i+1)
		round(s, U32(C))
		Commentf("End round %d\n", i+1)
	}
}

// round outputs the ASCON round function.
//
// C must be either a Register or int.
func round(s state, C Op) {
	Comment("Round constant")
	XORQ(C, s[2])

	Comment("Substitution")
	XORQ(s[4], s[0]) // s[0] ^= s[4]
	XORQ(s[3], s[4]) // s[4] ^= s[3]
	XORQ(s[1], s[2]) // s[2] ^= s[1]

	Comment("Keccak S-box")
	var t state
	t[0] = sbox(GP64(), s[0], s[1], s[2])
	t[1] = sbox(GP64(), s[1], s[2], s[3])
	t[2] = sbox(GP64(), s[2], s[3], s[4])
	t[3] = sbox(GP64(), s[3], s[4], s[0])
	t[4] = sbox(GP64(), s[4], s[0], s[1])

	Comment("Substituton")
	XORQ(t[0], t[1]) // t[1] ^= t[0]
	XORQ(t[4], t[0]) // t[0] ^= t[4]
	XORQ(t[2], t[3]) // t[3] ^= t[2]
	NOTQ(t[2])       // t[2] = ^t[2]

	Comment("Linear diffusion")
	ldiff(s[0], t[0], 19, 28)
	ldiff(s[1], t[1], 61, 39)
	ldiff(s[2], t[2], 1, 6)
	ldiff(s[3], t[3], 10, 17)
	ldiff(s[4], t[4], 7, 41)
}

// sbox sets z = a ^ (^b & c) and returns z.
func sbox(z, a, b, c Register) Register {
	nb := GP64()
	MOVQ(b, nb)
	NOTQ(nb)    // b = ^b
	MOVQ(c, z)  // z = c
	ANDQ(nb, z) // z = ^b & c
	XORQ(a, z)  // z = a ^ z
	return z
}

// ldiff sets z = x ^ rotr(x, n0) ^ rotr(x, n1).
func ldiff(z, x Register, n0, n1 uint64) {
	// z = rotr(x, n0)
	MOVQ(x, z)
	RORQ(U8(n0), z)

	// z = x ^ z
	XORQ(x, z)

	// t = rotr(x, n0)
	t := GP64()
	MOVQ(x, t)
	RORQ(U8(n1), t)

	XORQ(t, z) // z = z ^ t
}

type state [5]Register
