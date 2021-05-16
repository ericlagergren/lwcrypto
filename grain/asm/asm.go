package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../grain_amd64.s -stubs ../stub_amd64.go -pkg grain

func main() {
	Package("github.com/ericlagergren/lwcrypto/grain")
	ConstraintExpr("gc,!purego")

	declareKeystream()
	declareAccumulate()

	Generate()
}

type state struct {
	s   Component // *state
	acc Component // uint64
	reg Component // uint64
}

// loadState dereferences the *state in p and loads it into r.
func loadState(p Component, r Register) state {
	Comment("Load state")
	if _, err := p.Resolve(); err != nil {
		panic(err)
	}
	Load(p, r)
	s := p.Dereference(r)
	return state{
		s:   s,
		acc: s.Field("acc"),
		reg: s.Field("reg"),
	}
}

func (s state) store(l lfsr) {
	Commentf("Store %s: (lo, hi)", l.name)
	Store(l.lo, s.s.Field(l.name).Field("lo"))
	Store(l.hi, s.s.Field(l.name).Field("hi"))
}

func (s state) load(name string) lfsr {
	Commentf("Load %s: (lo, hi)", name)
	return lfsr{
		name: name,
		lo:   Load(s.s.Field(name).Field("lo"), GP64()),
		hi:   Load(s.s.Field(name).Field("hi"), GP64()),
	}
}

func (s state) lfsr() lfsr { return s.load("lfsr") }
func (s state) nfsr() lfsr { return s.load("nfsr") }

func declareKeystream() {
	TEXT("next", NOSPLIT, "func(s *state) uint32")
	Pragma("noescape")

	s := loadState(Param("s"), GP64())

	Comment("LFSR shifts")
	lfsr := s.lfsr()
	ln0 := named(GP64(), "ln0")
	ln1 := named(GP64(), "ln1")
	ln2 := named(GP64(), "ln2")
	ln3 := named(GP64(), "ln3")
	lfsr.words(ln0, ln1, ln2, ln3)

	t := named(GP64(), "<temp>")
	v := named(GP64(), "v")

	// v := ln0 ^ ln3
	Comment("v := ln ^ ln3")
	MOVQ(ln0, v)
	XORQ(ln3, v)

	// No longer used
	ln3 = nil

	// v ^= (ln1 ^ ln2) >> 6
	Comment("<temp> = ln1 ^ ln2")
	MOVQ(ln1, t)
	XORQ(ln2, t)
	shiftrAndXor(v, t, 6)

	// v ^= ln0 >> 7
	shiftrAndXor(v, ln0, 7)
	// v ^= ln2 >> 17
	shiftrAndXor(v, ln2, 17)

	// Update LFSR.
	lfsr.shift(v)
	s.store(lfsr)

	Comment("NFSR shifts")
	nfsr := s.nfsr()
	nn0 := named(GP64(), "nn0")
	nn1 := named(GP64(), "nn1")
	nn2 := named(GP64(), "nn2")
	nn3 := named(GP64(), "nn3")
	nfsr.words(nn0, nn1, nn2, nn3)

	u := named(v, "u")
	v = nil

	// u := ln0
	Comment("u := ln0")
	MOVQ(ln0, u)
	// u ^= nn0
	Comment("u ^= nn0")
	XORQ(nn0, u)
	// u ^= nn0 >> 26
	shiftrAndXor(u, nn0, 26)
	// u ^= nn3
	XORQ(nn3, u)
	// u ^= nn1 >> 24
	shiftrAndXor(u, nn1, 24)

	// u ^= ((nn0 & nn1) ^ nn2) >> 27
	Comment("<temp> = (nn0 & nn2) ^ nn2")
	MOVQ(nn1, t)
	ANDQ(nn0, t)
	XORQ(nn2, t)
	shiftrAndXor(u, t, 27)

	// u ^= (nn0 & nn2) >> 3
	Comment("<temp> = nn0 & nn2")
	MOVQ(nn2, t)
	ANDQ(nn0, t)
	shiftrAndXor(u, t, 3)

	// u ^= (nn0 >> 11) & (nn0 >> 13)
	shiftrAndXor(u, nn0, 11, nn0, 13)
	// u ^= (nn0 >> 17) & (nn0 >> 18)
	shiftrAndXor(u, nn0, 17, nn0, 18)
	// u ^= (nn1 >> 8) & (nn1 >> 16)
	shiftrAndXor(u, nn1, 8, nn1, 16)
	// u ^= (nn1 >> 29) & (nn2 >> 1)
	shiftrAndXor(u, nn1, 29, nn2, 1)
	// u ^= (nn2 >> 4) & (nn2 >> 20)
	shiftrAndXor(u, nn2, 4, nn2, 20)
	// u ^= (nn2 >> 24) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31)
	shiftrAndXor(u, nn2, 24, nn2, 28, nn2, 29, nn2, 31)
	// u ^= (nn0 >> 22) & (nn0 >> 24) & (nn0 >> 25)
	shiftrAndXor(u, nn0, 22, nn0, 24, nn0, 25)
	// u ^= (nn2 >> 6) & (nn2 >> 14) & (nn2 >> 18)
	shiftrAndXor(u, nn2, 6, nn2, 14, nn2, 18)

	// Update NFSR.
	nfsr.shift(u)
	s.store(nfsr)

	x := named(u, "x")
	u = nil

	// x := nn0 >> 2
	shrq3(x, nn0, 2)
	// x ^= nn0 >> 15
	shiftrAndXor(x, nn0, 15)
	// x ^= nn1 >> 4
	shiftrAndXor(x, nn1, 4)
	// x ^= nn1 >> 13
	shiftrAndXor(x, nn1, 13)
	// x ^= nn2
	XORQ(nn2, x)
	// x ^= nn2 >> 9
	shiftrAndXor(x, nn2, 9)
	// x ^= nn2 >> 25
	shiftrAndXor(x, nn2, 25)
	// x ^= ln2 >> 29
	shiftrAndXor(x, ln2, 29)
	// x ^= (nn0 >> 12) & (ln0 >> 8)
	shiftrAndXor(x, nn0, 12, ln0, 8)
	// x ^= (ln0 >> 13) & (ln0 >> 20)
	shiftrAndXor(x, ln0, 13, ln0, 20)
	// x ^= (nn2 >> 31) & (ln1 >> 10)
	shiftrAndXor(x, nn2, 31, ln1, 10)
	// x ^= (ln1 >> 28) & (ln2 >> 15)
	shiftrAndXor(x, ln1, 28, ln2, 15)
	// x ^= (nn0 >> 12) & (nn2 >> 31) & (ln2 >> 30)
	shiftrAndXor(x, nn0, 12, nn2, 31, ln2, 30)

	Comment("Store result")
	Store(x.As32(), ReturnIndex(0))

	RET()
}

type lfsr struct {
	name   string
	lo, hi Register
}

func (l lfsr) words(u0, u1, u2, u3 GPVirtual) {
	Comment("Load " + l.name + " words (u0, u1, u2, u3)")
	t := GP64()

	Comment("u0 = r.lo")
	MOVQ(l.lo, u0)

	Comment("u1 = r.lo>>32 | r.hi<<32")
	MOVQ(l.lo, u1)
	shrq(32, u1)
	MOVQ(l.hi, t)
	shlq(32, t)
	ORQ(t, u1)

	Comment("u2 = r.hi")
	MOVQ(l.hi, u2)

	Comment("u3 = r.hi>>32")
	MOVQ(l.hi, u3)
	shrq(32, u3)
}

// shift shifts off 32 low bits and replaces the high bits with
// x:
//
//    u = (u >> 32) | (x << 96)
//
func (l lfsr) shift(x Register) {
	t := GP64()

	Comment("lo = r.lo>>32 | r.hi<<(64-32)")
	shrq(32, l.lo)
	MOVQ(l.hi, t)
	shlq(32, t)
	ORQ(t, l.lo)

	Comment("r.hi>>32 | uint64(x)<<32")
	shrq(32, l.hi)
	MOVQ(x, t)
	shlq(32, t)
	ORQ(t, l.hi)
}

func declareAccumulate() {
	TEXT("accumulate", NOSPLIT, "func(reg, acc uint64, ms, pt uint16) (reg1, acc1 uint64)")
	Pragma("noescape")

	reg := Load(Param("reg"), GP64())
	acc := Load(Param("acc"), GP64())
	pt := Load(Param("pt"), GP16()).(GPVirtual)
	ms := Load(Param("ms"), GP64()).(GPVirtual)

	Comment("var acctmp uint16")
	acctmp := GP64()
	XORQ(acctmp, acctmp)

	Comment("regtmp := uint32(ms) << 16")
	regtmp := GP32()
	MOVWLZX(ms.As16(), regtmp)
	shll(16, regtmp)

	Comment("Zero register")
	zero := GP64()
	XORQ(zero, zero)

	for i := 0; i < 16; i++ {
		Comment(
			"mask, rem := ^uint64(0), uint64(0xffff)",
			"if pt&0x1 == 0 { mask, rem = 0, 0 }",
		)
		mask := GP64()
		rem := GP32()
		MOVQ(I32(-1), mask)
		MOVL(U32(0xffff), rem)

		switch s := 1 << i; {
		case s < math.MaxUint8:
			TESTB(U8(s), pt.As8())
		case s < math.MaxUint16:
			TESTW(U16(s), pt)
		default:
			panic("unreachable")
		}

		CMOVQEQ(zero, mask)
		CMOVLEQ(zero.As32(), rem)

		Comment("acc ^= reg & mask")
		ANDQ(reg, mask) // clobber mask
		XORQ(mask, acc)

		Comment("acctmp ^= uint16(regtmp & rem)")
		ANDL(regtmp, rem) // clobber rem
		XORW(rem.As16(), acctmp.As16())

		Comment("reg >>= 1")
		shrq(1, reg)

		// Last iteration does not matter.
		if i < 15 {
			Comment("regtmp >>= 1")
			SHRL(U8(1), regtmp)
		}
	}

	Comment("pt >>= 16")                   // 0
	Comment("reg |= uint64(ms) << 48")     // 1
	Comment("acc ^= uint64(acctmp) << 48") // 2

	shlq(48, ms)      // 1
	SHRW(U8(16), pt)  // 0
	shlq(48, acctmp)  // 2
	ORQ(ms, reg)      // 1
	XORQ(acctmp, acc) // 2

	Comment("Store results")
	Store(reg, ReturnIndex(0))
	Store(acc, ReturnIndex(1))

	RET()
}

// addr returns the address of the Component, or panics.
func addr(c Component) Mem {
	b, err := c.Resolve()
	if err != nil {
		panic(err)
	}
	return b.Addr
}

func shrq(x uint8, op Op) { SHRQ(U8(x), op) }
func shlq(x uint8, op Op) { SHLQ(U8(x), op) }
func shll(x uint8, op Op) { SHLL(U8(x), op) }

// shrq3 performs
//    t = o >> s
func shrq3(t, o Op, s uint8) {
	MOVQ(o, t)
	shrq(s, t)
}

// shiftrAndXor performs
//    z ^= (a >> b) & (c >> d) & ...
func shiftrAndXor(z Register, args ...interface{}) {
	if len(args)%2 != 0 || len(args) < 2 {
		panic("invalid number of arguments: " + strconv.Itoa(len(args)))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s ^= ", z)
	for i := 0; i < len(args); i += 2 {
		if i > 0 {
			b.WriteString(" & ")
		}
		fmt.Fprintf(&b, "(%s >> %d)", args[i], args[i+1])
	}
	Comment(b.String())

	next := func() (uint8, Op) {
		o := args[0].(Op)
		s := args[1].(int)
		if s < 0 || s > 64 {
			panic("shift out of range: " + strconv.Itoa(s))
		}
		args = args[2:]
		return uint8(s), o
	}

	t := GP64()
	s, o := next()
	shrq3(t, o, s)

	var t2 Register
	for len(args) > 0 {
		if t2 == nil {
			t2 = GP64()
		}
		s, o := next()
		shrq3(t2, o, s)
		ANDQ(t2, t)
	}

	XORQ(t, z)
}

func named(r GPVirtual, name string) GPVirtual {
	return namedRegister{r, name}
}

type namedRegister struct {
	GPVirtual
	name string
}

func (n namedRegister) String() string {
	return n.name
}
