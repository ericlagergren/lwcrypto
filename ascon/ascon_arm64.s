//go:build gc && !purego
// +build gc,!purego

#include "textflag.h"

// R0-R10 are reserved for permutations.

#define s0 R0
#define s1 R1
#define s2 R2
#define s3 R3
#define s4 R4

#define t0 R5
#define t1 R6
#define t2 R7
#define t3 R8
#define t4 R9

#define s_ptr R10

// PERM_LOAD loads *state from s+0(FP) into s_ptr.
#define PERM_LOAD \
	MOVD s+0(FP), s_ptr;        \
	LDP  0*16(s_ptr), (s0, s1); \
	LDP  1*16(s_ptr), (s2, s3); \
	MOVD 2*16(s_ptr), s4

// PERM_STORE stores s{0,1,2,4} into s_ptr.
#define PERM_STORE \
	STP  (s0, s1), 0*16(s_ptr); \
	STP  (s2, s3), 1*16(s_ptr); \
	MOVD s4, 2*16(s_ptr)

// ROUND completes one permutation round.
//
// Uses s{0,1,2,3,4} and t{0,1,2,3,4}.
#define ROUND(C) \
	/* Round constant */                             \
	EOR C, s2, s2; /* s2 ^= C */                     \
	                                                 \
	/* Substitution */                               \
	EOR s4, s0, s0; /* s0 ^= s4 */                   \
	EOR s3, s4, s4; /* s4 ^= s3 */                   \
	EOR s1, s2, s2; /* s2 ^= s1 */                   \
	                                                 \
	/* Keccak S-box */                               \
	BIC s1, s2, t0; /* t0 := ^s1 & s2 */             \
	BIC s2, s3, t1; /* t1 := ^s2 & s3 */             \
	BIC s3, s4, t2; /* t2 := ^s3 & s4 */             \
	BIC s4, s0, t3; /* t3 := ^s4 & s0 */             \
	BIC s0, s1, t4; /* t4 := ^s0 & s1 */             \
	                                                 \
	EOR s0, t0, t0; /* t0 ^= s0 */                   \
	EOR s1, t1, t1; /* t1 ^= s1*/                    \
	EOR s2, t2, t2; /* t2 ^= s2 */                   \
	EOR s3, t3, t3; /* t3 ^= s3 */                   \
	EOR s4, t4, t4; /* t4 ^= s4 */                   \
	                                                 \
	/* Substitution */                               \
	EOR t0, t1, t1; /* t1 ^= t0 */                   \
	EOR t4, t0, t0; /* t0 ^= t4 */                   \
	EOR t2, t3, t3; /* t3 ^= t2 */                   \
	MVN t2, t2; /* t2 = ^t2 */                       \
	                                                 \
	EOR t0@>19, t0, s0; /* s0 = t0 ^ rotr(t0, 19) */ \
	EOR t1@>61, t1, s1; /* s1 = t1 ^ rotr(t1, 61) */ \
	EOR t2@>1, t2, s2; /* s2 = t2 ^ rotr(t2, 1) */   \
	EOR t3@>10, t3, s3; /* s3 = t3 ^ rotr(t3, 10) */ \
	EOR t4@>7, t4, s4; /* s4 = t4 ^ rotr(t4, 7) */   \
	                                                 \
	EOR t0@>28, s0, s0; /* s0 ^= rotr(t0, 28) */     \
	EOR t1@>39, s1, s1; /* s1 ^= rotr(t1, 39) */     \
	EOR t2@>6, s2, s2; /* s2 ^= rotr(t2, 6) */       \
	EOR t3@>17, s3, s3; /* s3 ^= rotr(t3, 17) */     \
	EOR t4@>41, s4, s4; /* s4 ^= rotr(t4, 41) */     \
	                                                 \
	/* So the comments line up correctly */          \
	NOP

#define P12 \
	ROUND($0xf0); \
	ROUND($0xe1); \
	ROUND($0xd2); \
	ROUND($0xc3); \
	ROUND($0xb4); \
	ROUND($0xa5); \
	ROUND($0x96); \
	ROUND($0x87); \
	ROUND($0x78); \
	ROUND($0x69); \
	ROUND($0x5a); \
	ROUND($0x4b)

#define P8 \
	ROUND($0xb4); \
	ROUND($0xa5); \
	ROUND($0x96); \
	ROUND($0x87); \
	ROUND($0x78); \
	ROUND($0x69); \
	ROUND($0x5a); \
	ROUND($0x4b)

#define P6 \
	ROUND($0x96); \
	ROUND($0x87); \
	ROUND($0x78); \
	ROUND($0x69); \
	ROUND($0x5a); \
	ROUND($0x4b)

// func p12(s *state)
TEXT ·p12(SB), NOSPLIT, $0-8
	PERM_LOAD
	P12
	PERM_STORE
	RET

// func p8(s *state)
TEXT ·p8(SB), NOSPLIT, $0-8
	PERM_LOAD
	P8
	PERM_STORE
	RET

// func p6(s *state)
TEXT ·p6(SB), NOSPLIT, $0-8
	PERM_LOAD
	P6
	PERM_STORE
	RET

// func round(s *state, C uint64)
TEXT ·round(SB), NOSPLIT, $0-16
	PERM_LOAD
	MOVD C+8(FP), R11
	ROUND(R11)
	PERM_STORE
	RET

// func additionalData128a(s *state, ad []byte)
TEXT ·additionalData128a(SB), NOSPLIT, $0-32
#define ad_ptr R11
#define remain R12
#define a0 R13
#define a1 R14

	PERM_LOAD
	MOVD ad_base+8(FP), ad_ptr
	MOVD ad_len+16(FP), remain
	ADD  $16, remain

loop:
	LDP.P 16(ad_ptr), (a0, a1)
	SUB   $16, remain
	CMP   $16, remain
	REV   a0, a0
	REV   a1, a1
	EOR   a0, s0, s0
	EOR   a1, s1, s1
	P8
	BGT   loop

	PERM_STORE
	RET

#undef ad_ptr
#undef remain
#undef a0
#undef a1

// func encryptBlocks128a(s *state, dst, src []byte)
TEXT ·encryptBlocks128a(SB), NOSPLIT, $0-56
#define src_ptr R11
#define dst_ptr R12
#define remain R13
#define c0 R14
#define c1 R15

	PERM_LOAD
	MOVD dst_base+8(FP), dst_ptr
	MOVD src_base+32(FP), src_ptr
	MOVD src_len+40(FP), remain
	ADD  $16, remain

loop:
	LDP.P 16(src_ptr), (c0, c1)
	SUB   $16, remain
	CMP   $16, remain
	REV   c0, c0
	REV   c1, c1
	EOR   c0, s0, s0
	EOR   c1, s1, s1
	REV   s0, c0
	REV   s1, c1
	STP.P (c0, c1), 16(dst_ptr)
	P8
	BGT   loop

	PERM_STORE
	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef c0
#undef c1

// func decryptBlocks128a(s *state, dst, src []byte)
TEXT ·decryptBlocks128a(SB), NOSPLIT, $0-56
#define src_ptr R11
#define dst_ptr R12
#define remain R13
#define c0 R14
#define c1 R15

	PERM_LOAD
	MOVD dst_base+8(FP), dst_ptr
	MOVD src_base+32(FP), src_ptr
	MOVD src_len+40(FP), remain
	ADD  $16, remain

loop:
	LDP.P 16(src_ptr), (c0, c1)
	SUB   $16, remain
	CMP   $16, remain
	REV   c0, c0
	REV   c1, c1
	EOR   c0, s0, s0            // clobber s0
	EOR   c1, s1, s1            // clobber s1
	REV   s0, s0
	REV   s1, s1
	STP.P (s0, s1), 16(dst_ptr)
	MOVD  c0, s0                // reassign s0
	MOVD  c1, s1                // reassign s1
	P8
	BGT   loop

	PERM_STORE
	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef c0
#undef c1
