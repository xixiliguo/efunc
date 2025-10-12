package funcgraph

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

var rawData = []byte{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 50, 6, 160, 101, 138, 255, 255, 0, 137, 113,
	66, 101, 138, 255, 255, 208, 31, 5, 65, 101, 138, 255, 255, 224, 249, 191, 134, 255, 255,
	255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 136, 0, 0, 3, 0, 14, 4, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 190, 1, 66, 101, 138, 255, 255, 88, 190, 1, 66, 101, 138, 255,
	255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 192, 198, 200, 68, 101, 138, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 32, 18,
	45, 66, 101, 138, 255, 255, 128, 28, 21, 66, 101, 138, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 72, 33,
	5, 65, 101, 138, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
}

func mustNewOpt(tb testing.TB) *dumpOption {
	tb.Helper()
	opt, err := NewDumpOption()
	if err != nil {
		tb.Fatalf("%s", err)
	}
	return opt
}

func mustTypeByName(tb testing.TB, name string, typ **btf.Struct) {
	tb.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		tb.Fatalf("%s", err)
	}
	err = spec.TypeByName(name, typ)
	if err != nil {
		tb.Fatalf("%s", err)
	}
}

func BenchmarkDumpDataByBTF(b *testing.B) {
	opt := mustNewOpt(b)
	name := "file"
	var typ *btf.Struct
	mustTypeByName(b, name, &typ)
	for b.Loop() {
		opt.Reset(rawData, false, false, 0, 0, false)
		opt.dumpDataByBTF(name, typ, 0, 0, 0)
	}
}
