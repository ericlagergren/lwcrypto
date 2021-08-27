//go:build !(amd64 || arm64 || gc) || purego
// +build !amd64,!arm64,!gc purego

package ascon

func round(s *state, C uint64) {
	roundGeneric(s, C)
}

func p12(s *state) {
	p12Generic(s)
}

func p8(s *state) {
	p8Generic(s)
}

func p6(s *state) {
	p6Generic(s)
}
