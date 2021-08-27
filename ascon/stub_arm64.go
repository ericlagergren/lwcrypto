//go:build gc && !purego
// +build gc,!purego

package ascon

//go:noescape
func p12(s *state)

//go:noescape
func p8(s *state)

//go:noescape
func p6(s *state)

//go:noescape
func round(s *state, C uint64)
