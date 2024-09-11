//go:build 386 || amd64
// +build 386 amd64

package funcgraph

import (
	"github.com/cilium/ebpf/btf"
)

const (
	MaxRegParas = 6
)

var RegToStr = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
var RetReg = "rax"

func idxInReg(idx int) bool {
	return idx < MaxRegParas
}

func (f *FuncInfo) InitArgsRet() {

	proto := f.Btfinfo.Type.(*btf.FuncProto)
	regIdx := 0
	if sz, _ := btf.Sizeof(proto.Return); sz > 16 {
		regIdx = 1
	}
	stackOff := 1

	for _, p := range proto.Params {
		arg := Arg{
			Name: p.Name,
			Typ:  p.Type,
		}
		sz, _ := btf.Sizeof(p.Type)
		if sz <= 8 && idxInReg(regIdx) {
			arg.Kind = REG
			arg.IdxOff = uint32(regIdx)
			regIdx += 1
		} else if sz <= 16 && idxInReg(regIdx) && idxInReg(regIdx+1) {
			arg.Kind = REG
			arg.IdxOff = uint32(regIdx)
			regIdx += 2
		} else {
			arg.Kind = STACK
			arg.IdxOff = uint32(stackOff)
			stackOff += (sz + 7) / 8
		}
		arg.Size = sz
		f.args = append(f.args, arg)
	}

	sz, _ := btf.Sizeof(proto.Return)
	if sz <= 16 {
		f.ret = Arg{"ret", RET_REG, 0, sz, proto.Return}
	} else {
		f.ret = Arg{"ret", RET_STACK, 0, sz, proto.Return}
	}
}
