package funcgraph

import (
	"sync"

	"github.com/cilium/ebpf/btf"
)

var specCache = make(map[string]*btf.Spec)
var baseSpec = sync.OnceValues(func() (*btf.Spec, error) {
	return btf.LoadKernelSpec()
})

func LoadBTFSpec(mod string) (*btf.Spec, error) {

	if mod == "" || mod == "vmlinux" {
		return baseSpec()
	}

	if spec, ok := specCache[mod]; ok {
		return spec, nil
	}

	h, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.Name == mod
	})
	if err != nil {
		return nil, err
	}
	base, err := baseSpec()
	if err != nil {
		return nil, err
	}
	spec, err := h.Spec(base)
	if err != nil {
		return spec, err
	}
	specCache[mod] = spec
	return spec, nil

}

func FlushBTFSpec() {
	baseSpec = nil
	specCache = nil
	btf.FlushKernelSpec()
}
