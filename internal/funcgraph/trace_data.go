package funcgraph

import "github.com/cilium/ebpf/btf"

type ArgType = funcgraphArgType

const (
	REG       ArgType = funcgraphArgTypeREG
	STACK     ArgType = funcgraphArgTypeSTACK
	ADDR      ArgType = funcgraphArgTypeADDR
	RET_REG   ArgType = funcgraphArgTypeRET_REG
	RET_STACK ArgType = funcgraphArgTypeRET_STACK
	REG_PTR   ArgType = funcgraphArgTypeREG_PTR
	STACK_PTR ArgType = funcgraphArgTypeSTACK_PTR
)

type TraceData struct {
	name        string
	onEntry     bool
	argType     ArgType
	IdxOff      uint32
	typ         btf.Type
	offsets     []uint16
	size        int
	bitOff      uint8
	bitSize     uint8
	isStr       bool
	isDefer     bool
	isSign      bool
	CmpOperator uint8
	Target      uint64
}

func (t *TraceData) flags() (flag uint8) {
	if t.isStr {
		flag |= uint8(funcgraphTraceDataFlagsDATA_STR)
	}
	if t.isDefer {
		flag |= uint8(funcgraphTraceDataFlagsDATA_DEREF)
	}
	if t.isSign {
		flag |= uint8(funcgraphTraceDataFlagsDATA_SIGN)
	}
	return
}
