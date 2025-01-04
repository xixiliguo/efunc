package funcgraph

import "github.com/cilium/ebpf/btf"

type ArgKind = funcgraphArgKind

const (
	REG       ArgKind = funcgraphArgKindREG
	STACK     ArgKind = funcgraphArgKindSTACK
	ADDR      ArgKind = funcgraphArgKindADDR
	RET_REG   ArgKind = funcgraphArgKindRET_REG
	RET_STACK ArgKind = funcgraphArgKindRET_STACK
	REG_PTR   ArgKind = funcgraphArgKindREG_PTR
	STACK_PTR ArgKind = funcgraphArgKindSTACK_PTR
)

type TraceData struct {
	name        string
	onEntry     bool
	argKind     ArgKind
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
	TargetStr   string
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
