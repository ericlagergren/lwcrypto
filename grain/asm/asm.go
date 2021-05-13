package main

import (
	"fmt"
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
	s     Component // *state
	i     Component // int
	count Component // int
	acc   Component // uint64
	reg   Component // uint64
	wtf   Component
}

// loadState loads the *state in p into r.
func loadState(p Component, r Register) state {
	s := Dereference(p)
	return state{
		s:     p,
		i:     s.Field("i"),
		count: s.Field("count"),
		acc:   s.Field("acc"),
		reg:   s.Field("reg"),
		wtf:   s.Field("wtf"),
	}
}

// lfsr returns the address of the lfsr field.
func (s state) lfsr(r Register) Mem {
	return Mem{
		Base: Load(s.s, r),
		Disp: lfsrOffset,
	}
}

// nfsr returns the address of the nfsr field.
func (s state) nfsr(r Register) Mem {
	return Mem{
		Base: Load(s.s, r),
		Disp: nfsrOffset,
	}
}

// Keep this in sync with ../grain.go, otherwise Bad Things will
// happen.
const (
	lfsrSize   = 1040
	lfsrOffset = 4 * 4
	nfsrOffset = lfsrOffset + lfsrSize*4
)

func declareAccumulate() {
	TEXT("accumulate", NOSPLIT, "func(s *state, ms, pt uint16)")
	Pragma("noescape")

	s := loadState(Param("s"), GP64())
	reg := Load(s.reg, GP64())
	acc := Load(s.acc, GP64())
	pt := Load(Param("pt"), GP16())
	ms := Load(Param("ms"), GP16()).(GPVirtual)

	acctmp := GP16()

	Comment("regtmp := uint32(ms) << 16")
	regtmp := GP32()
	MOVWLZX(ms, regtmp)
	shll(16, regtmp)

	mask := GP64()
	rem := GP32()
	t64 := GP64() // temp
	t32 := GP32() // temp

	Comment("Registerized constants")
	// MOVQ $-1 is shorter than MOVQ $0xffffffffffffffff.
	allOnes := GP64()
	MOVQ(I32(-1), allOnes)

	low16 := GP32()
	MOVL(U32(0xffff), low16)

	for i := 0; i < 16; i++ {
		Comment(
			"var mask uint64",
			"if pt&0x1 != 0 { mask = ^uint64(0) }",
		)
		XORQ(mask, mask)
		TESTW(U16(1), pt)
		CMOVQNE(allOnes, mask)

		Comment("s.acc ^= s.reg & mask")
		MOVQ(reg, t64)
		ANDQ(mask, t64)
		XORQ(t64, acc)

		Comment("s.reg >>= 1")
		shrq(1, reg) // s.reg >>= 1

		Comment(
			"var rem uint32",
			"if pt&0x1 != 0 { rem = 0xffff }",
		)
		XORL(rem, rem)
		TESTW(U16(1), pt)
		CMOVLNE(low16, rem)

		Comment("acctmp ^= uint16(regtmp & rem)")
		MOVL(regtmp, t32)
		ANDL(rem, t32)
		XORW(t32.As16(), acctmp)

		p := GP32()
		MOVL(regtmp, p)
		ANDL(rem, p)
		MOVL(p, addr(s.wtf.Index(i)))

		// Last iteration does not matter.
		Comment("regtmp >>= 1")
		SHRL(U8(1), regtmp) // regtmp >>= 1

		Comment("pt >>= 1")
		SHRW(U8(1), pt) // pt >>= 1
	}

	Comment("s.reg |= uint64(ms) << 48")
	MOVWQZX(ms, t64)
	shlq(48, t64)
	ORQ(t64, reg)

	Comment("s.acc ^= uint64(acctmp) << 48")
	MOVWQZX(acctmp, t64)
	shlq(48, t64) //acctmp.As64())
	XORQ(t64, acc)

	Comment("Store registerized fields")
	MOVQ(reg, addr(s.reg))
	MOVQ(acc, addr(s.acc))

	RET()
}

func declareKeystream() {
	TEXT("next", NOSPLIT, "func(s *state) uint32")
	Pragma("noescape")

	s := loadState(Param("s"), GP64())
	i := Load(s.i, GP64())
	count := Load(s.count, GP64())

	Comment("LFSR")
	lfsr := s.lfsr(GP64())

	ln0 := named(GP64(), "ln0")
	ln1 := named(GP64(), "ln1")
	ln2 := named(GP64(), "ln2")
	ln3 := named(GP64(), "ln3")

	for j, r := range []Register{ln0, ln1, ln2, ln3.As32()} {
		if r.Size() == 4 {
			MOVL(lfsr.Idx(i, 4).Offset(j*4), r)
		} else {
			MOVQ(lfsr.Idx(i, 4).Offset(j*4), r)
		}
	}

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

	Comment("s.lfsr[s.count] = uint32(v)")
	MOVL(v.As32(), lfsr.Idx(count, 4))

	Comment("NFSR")
	nfsr := s.nfsr(GP64())

	nn0 := named(GP64(), "nn0")
	nn1 := named(GP64(), "nn1")
	nn2 := named(GP64(), "nn2")
	nn3 := named(GP64(), "nn3")

	for j, r := range []Register{nn0, nn1, nn2, nn3.As32()} {
		if r.Size() == 4 {
			MOVL(nfsr.Idx(i, 4).Offset(j*4), r)
		} else {
			MOVQ(nfsr.Idx(i, 4).Offset(j*4), r)
		}
	}

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

	Comment("s.nfsr[s.count] = uint32(u)")
	MOVL(u.As32(), nfsr.Idx(count, 4))

	Comment("s.count++")
	INCQ(count)

	Comment("s.i++")
	INCQ(i)

	// if s.count >= len(s.lfsr) {
	// TODO: don't hardcode size
	CMPQ(count, I32(lfsrSize))
	JGE(LabelRef("start_reinit"))

	Label("end_reinit")

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

	Comment("Store updated s.i and s.count")
	MOVQ(i, addr(s.i))
	MOVQ(count, addr(s.count))

	Comment("Store result")
	Store(x.As32(), ReturnIndex(0))

	RET()

	Label("start_reinit")
	{
		for j := 0; j < 2; j++ {
			MOVQ(lfsr.Idx(i, 4).Offset(j*8), t)
			MOVQ(t, lfsr.Offset(j*8))
		}
		for j := 0; j < 2; j++ {
			MOVQ(nfsr.Idx(i, 4).Offset(j*8), t)
			MOVQ(t, nfsr.Offset(j*8))
		}

		XORQ(i, i)          // s.i = 0
		MOVQ(U32(4), count) // s.count = 4

		JMP(LabelRef("end_reinit"))
	}
}

// addr returns the address of the Component, or panics.
func addr(c Component) Mem {
	b, err := c.Resolve()
	if err != nil {
		panic(err)
	}
	return b.Addr
}

// load64 reads 64 bits from m into a new register.
func load64(m Mem, r Register) Register {
	MOVQ(m, r)
	return r
}

// load32 reads 32 bits from m into a new register.
func load32(m Mem, r GPVirtual) Register {
	MOVL(m, r.As32())
	return r
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
