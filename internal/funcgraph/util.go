package funcgraph

import (
	"github.com/cilium/ebpf/btf"
)

var btfCache = btf.NewCache()

func LoadBTFSpec(mod string) (*btf.Spec, error) {

	if mod == "" || mod == "vmlinux" {
		return btfCache.Kernel()
	}
	return btfCache.Module(mod)
}

func FlushBTFSpec() {
	btfCache = nil
	btf.FlushKernelSpec()
}
