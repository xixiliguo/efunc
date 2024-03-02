package main

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

func BenchmarkDumpDataByBTF(b *testing.B) {
	opt, err := NewDumpOption()
	if err != nil {
		b.Fatalf("%s", err)
	}
	opt.Reset(rawData, false, 0)

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		b.Fatalf("%s", err)
	}
	name := "file"
	var typ *btf.Struct
	iter := spec.Iterate()
	for iter.Next() {
		if s, ok := iter.Type.(*btf.Struct); ok {
			if s.Name == name {
				typ = s
			}
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		opt.Reset(rawData, false, 0)
		opt.dumpDataByBTF(name, typ)
	}
}
