//go:build gc && !purego
// +build gc,!purego

#include "textflag.h"

#define s_ptr R26
#define rc R25

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

// ROUND completes one permutation round.
//
// Uses s{0,1,2,3,4} and t{0,1,2,3,4}.
//
// C must start with $.
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
	EOR t0@>28, s0, s0; /* s0 ^= rotr(t0, 28) */     \
	                                                 \
	EOR t1@>61, t1, s1; /* s1 = t1 ^ rotr(t1, 61) */ \
	EOR t1@>39, s1, s1; /* s1 ^= rotr(t1, 39) */     \
	                                                 \
	EOR t2@>1, t2, s2; /* s2 = t2 ^ rotr(t2, 1) */   \
	EOR t2@>6, s2, s2; /* s2 ^= rotr(t2, 6) */       \
	                                                 \
	EOR t3@>10, t3, s3; /* s3 = t3 ^ rotr(t3, 10) */ \
	EOR t3@>17, s3, s3; /* s3 ^= rotr(t3, 17) */     \
	                                                 \
	EOR t4@>7, t4, s4; /* s4 = t4 ^ rotr(t4, 7) */   \
	EOR t4@>41, s4, s4; /* s4 ^= rotr(t4, 41) */     \
	                                                 \
	/* So the comments line up correctly */          \
	NOP

// PERM_LOAD loads *state from s+0(FP) into s_ptr.
#define PERM_LOAD \
	MOVD s+0(FP), s_ptr;        \
	                            \
	LDP  0*16(s_ptr), (s0, s1); \
	LDP  1*16(s_ptr), (s2, s3); \
	MOVD 2*16(s_ptr), s4

// PERM_STORE stores s{0,1,2,4} into s_ptr.
#define PERM_STORE \
	STP  (s0, s1), 0*16(s_ptr); \
	STP  (s2, s3), 1*16(s_ptr); \
	MOVD s4, 2*16(s_ptr)

// func p12(s *state)
TEXT ·p12(SB), NOSPLIT, $0-8
	PERM_LOAD
	ROUND($0xf0)
	ROUND($0xe1)
	ROUND($0xd2)
	ROUND($0xc3)
	ROUND($0xb4)
	ROUND($0xa5)
	ROUND($0x96)
	ROUND($0x87)
	ROUND($0x78)
	ROUND($0x69)
	ROUND($0x5a)
	ROUND($0x4b)
	PERM_STORE
	RET

// func p8(s *state)
TEXT ·p8(SB), NOSPLIT, $0-8
	PERM_LOAD
	ROUND($0xb4)
	ROUND($0xa5)
	ROUND($0x96)
	ROUND($0x87)
	ROUND($0x78)
	ROUND($0x69)
	ROUND($0x5a)
	ROUND($0x4b)
	PERM_STORE
	RET

// func p6(s *state)
TEXT ·p6(SB), NOSPLIT, $0-8
	PERM_LOAD
	ROUND($0x96)
	ROUND($0x87)
	ROUND($0x78)
	ROUND($0x69)
	ROUND($0x5a)
	ROUND($0x4b)
	PERM_STORE
	RET

// func round(s *state, C uint64)
TEXT ·round(SB), NOSPLIT, $0-16
	PERM_LOAD
	MOVD C+8(FP), rc
	ROUND(rc)
	PERM_STORE
	RET
