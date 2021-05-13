// +build !grain_cgo

package grain

import (
	"math/rand"
	"reflect"
	"testing/quick"
)

func setField(rng *rand.Rand, v interface{}) {
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Ptr {
		panic("bad kind: " + t.Kind().String())
	}
	rv, ok := quick.Value(t.Elem(), rng)
	if !ok {
		panic("got false")
	}
	reflect.ValueOf(v).Elem().Set(rv)
}

func randGrain(rng *rand.Rand) *state {
	var g state
	setField(rng, &g.key)
	setField(rng, &g.lfsr)
	setField(rng, &g.nfsr)
	setField(rng, &g.i)
	setField(rng, &g.count)
	setField(rng, &g.acc)
	setField(rng, &g.reg)
	return &g
}
