// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package funcgraph

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type funcgraphArgAddr uint32

const (
	funcgraphArgAddrBASE_LEN    funcgraphArgAddr = 4
	funcgraphArgAddrBASE_SHIFT  funcgraphArgAddr = 28
	funcgraphArgAddrINDEX_LEN   funcgraphArgAddr = 4
	funcgraphArgAddrINDEX_SHIFT funcgraphArgAddr = 24
	funcgraphArgAddrSCALE_LEN   funcgraphArgAddr = 8
	funcgraphArgAddrSCALE_SHIFT funcgraphArgAddr = 16
	funcgraphArgAddrIMM_LEN     funcgraphArgAddr = 16
	funcgraphArgAddrIMM_SHIFT   funcgraphArgAddr = 0
)

type funcgraphArgKind uint32

const (
	funcgraphArgKindREG       funcgraphArgKind = 0
	funcgraphArgKindSTACK     funcgraphArgKind = 1
	funcgraphArgKindADDR      funcgraphArgKind = 2
	funcgraphArgKindRET_REG   funcgraphArgKind = 3
	funcgraphArgKindRET_STACK funcgraphArgKind = 4
	funcgraphArgKindREG_PTR   funcgraphArgKind = 5
	funcgraphArgKindSTACK_PTR funcgraphArgKind = 6
)

type funcgraphCallEvent struct {
	Type      uint8
	_         [7]byte
	Task      uint64
	Pid       uint32
	Tid       uint32
	GroupComm [16]uint8
	Comm      [16]uint8
	Ips       [32]uint64
	Durations [32]uint64
	Kstack    [128]uint64
	KstackSz  uint64
	StartTime uint64
	EndTime   uint64
	Depth     uint64
	NextSeqId uint64
}

type funcgraphEventData struct {
	DataLen uint32
	DataOff [7]int32
	Data    [0]uint8
}

type funcgraphFunc struct {
	Id            uint32
	IsMainEntry   bool
	Name          [40]int8
	TraceCnt      uint8
	HaveFilter    bool
	_             [1]byte
	Trace         [7]funcgraphTraceData
	RetTraceCnt   uint8
	HaveRetFilter bool
	_             [6]byte
	RetTrace      [7]funcgraphTraceData
}

type funcgraphFuncBasic struct {
	Id          uint32
	IsMainEntry bool
	Name        [40]int8
	_           [3]byte
}

type funcgraphFuncEvent struct {
	Type     uint8
	_        [7]byte
	Task     uint64
	CpuId    uint32
	_        [4]byte
	Depth    uint64
	SeqId    uint64
	Ip       uint64
	Id       uint32
	HaveData bool
	_        [3]byte
	Duration uint64
	Records  [16]uint64
	Buf      [0]funcgraphEventData
}

type funcgraphStartEvent struct {
	Type uint8
	_    [7]byte
	Task uint64
}

type funcgraphTraceConstant uint32

const (
	funcgraphTraceConstantPARA_LEN            funcgraphTraceConstant = 16
	funcgraphTraceConstantMAX_TRACE_FIELD_LEN funcgraphTraceConstant = 5
	funcgraphTraceConstantMAX_TRACES          funcgraphTraceConstant = 7
	funcgraphTraceConstantMAX_TARGET_LEN      funcgraphTraceConstant = 16
)

type funcgraphTraceData struct {
	ArgKind     funcgraphArgKind
	ArgLoc      uint32
	FieldCnt    uint8
	_           [1]byte
	Offsets     [5]uint16
	Size        uint32
	BitOff      uint8
	BitSize     uint8
	Flags       uint8
	CmpOperator uint8
	_           [4]byte
	Target      uint64
	TargetStr   [16]int8
}

type funcgraphTraceDataFlags uint32

const (
	funcgraphTraceDataFlagsDATA_STR        funcgraphTraceDataFlags = 1
	funcgraphTraceDataFlagsDATA_DEREF      funcgraphTraceDataFlags = 2
	funcgraphTraceDataFlagsDATA_SIGN       funcgraphTraceDataFlags = 4
	funcgraphTraceDataFlagsDATA_CHAR_ARRAY funcgraphTraceDataFlags = 8
)

// loadFuncgraph returns the embedded CollectionSpec for funcgraph.
func loadFuncgraph() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FuncgraphBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load funcgraph: %w", err)
	}

	return spec, err
}

// loadFuncgraphObjects loads funcgraph and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*funcgraphObjects
//	*funcgraphPrograms
//	*funcgraphMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFuncgraphObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFuncgraph()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// funcgraphSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type funcgraphSpecs struct {
	funcgraphProgramSpecs
	funcgraphMapSpecs
	funcgraphVariableSpecs
}

// funcgraphProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type funcgraphProgramSpecs struct {
	Funcentry  *ebpf.ProgramSpec `ebpf:"funcentry"`
	Funcret    *ebpf.ProgramSpec `ebpf:"funcret"`
	HandleFork *ebpf.ProgramSpec `ebpf:"handle_fork"`
	HandleFree *ebpf.ProgramSpec `ebpf:"handle_free"`
}

// funcgraphMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type funcgraphMapSpecs struct {
	CallEvents    *ebpf.MapSpec `ebpf:"call_events"`
	CommsFilter   *ebpf.MapSpec `ebpf:"comms_filter"`
	EventStats    *ebpf.MapSpec `ebpf:"event_stats"`
	Events        *ebpf.MapSpec `ebpf:"events"`
	FuncBasicInfo *ebpf.MapSpec `ebpf:"func_basic_info"`
	FuncInfo      *ebpf.MapSpec `ebpf:"func_info"`
	PidsFilter    *ebpf.MapSpec `ebpf:"pids_filter"`
	Ready         *ebpf.MapSpec `ebpf:"ready"`
}

// funcgraphVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type funcgraphVariableSpecs struct {
	ArgAddrUnused        *ebpf.VariableSpec `ebpf:"arg_addr_unused"`
	ArgTypeUnused        *ebpf.VariableSpec `ebpf:"arg_type_unused"`
	CommAllowCnt         *ebpf.VariableSpec `ebpf:"comm_allow_cnt"`
	CommDenyCnt          *ebpf.VariableSpec `ebpf:"comm_deny_cnt"`
	DurationMs           *ebpf.VariableSpec `ebpf:"duration_ms"`
	EntryUnused          *ebpf.VariableSpec `ebpf:"entry_unused"`
	EventDataUnused      *ebpf.VariableSpec `ebpf:"event_data_unused"`
	HasBpfGetFuncIp      *ebpf.VariableSpec `ebpf:"has_bpf_get_func_ip"`
	KretOffset           *ebpf.VariableSpec `ebpf:"kret_offset"`
	MaxDepth             *ebpf.VariableSpec `ebpf:"max_depth"`
	MaxTraceBuf          *ebpf.VariableSpec `ebpf:"max_trace_buf"`
	MaxTraceData         *ebpf.VariableSpec `ebpf:"max_trace_data"`
	PidAllowCnt          *ebpf.VariableSpec `ebpf:"pid_allow_cnt"`
	PidDenyCnt           *ebpf.VariableSpec `ebpf:"pid_deny_cnt"`
	StartUnused          *ebpf.VariableSpec `ebpf:"start_unused"`
	TraceConstantUnused  *ebpf.VariableSpec `ebpf:"trace_constant_unused"`
	TraceDataFlagsUnused *ebpf.VariableSpec `ebpf:"trace_data_flags_unused"`
	TraceUnused          *ebpf.VariableSpec `ebpf:"trace_unused"`
	Verbose              *ebpf.VariableSpec `ebpf:"verbose"`
}

// funcgraphObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFuncgraphObjects or ebpf.CollectionSpec.LoadAndAssign.
type funcgraphObjects struct {
	funcgraphPrograms
	funcgraphMaps
	funcgraphVariables
}

func (o *funcgraphObjects) Close() error {
	return _FuncgraphClose(
		&o.funcgraphPrograms,
		&o.funcgraphMaps,
	)
}

// funcgraphMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFuncgraphObjects or ebpf.CollectionSpec.LoadAndAssign.
type funcgraphMaps struct {
	CallEvents    *ebpf.Map `ebpf:"call_events"`
	CommsFilter   *ebpf.Map `ebpf:"comms_filter"`
	EventStats    *ebpf.Map `ebpf:"event_stats"`
	Events        *ebpf.Map `ebpf:"events"`
	FuncBasicInfo *ebpf.Map `ebpf:"func_basic_info"`
	FuncInfo      *ebpf.Map `ebpf:"func_info"`
	PidsFilter    *ebpf.Map `ebpf:"pids_filter"`
	Ready         *ebpf.Map `ebpf:"ready"`
}

func (m *funcgraphMaps) Close() error {
	return _FuncgraphClose(
		m.CallEvents,
		m.CommsFilter,
		m.EventStats,
		m.Events,
		m.FuncBasicInfo,
		m.FuncInfo,
		m.PidsFilter,
		m.Ready,
	)
}

// funcgraphVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadFuncgraphObjects or ebpf.CollectionSpec.LoadAndAssign.
type funcgraphVariables struct {
	ArgAddrUnused        *ebpf.Variable `ebpf:"arg_addr_unused"`
	ArgTypeUnused        *ebpf.Variable `ebpf:"arg_type_unused"`
	CommAllowCnt         *ebpf.Variable `ebpf:"comm_allow_cnt"`
	CommDenyCnt          *ebpf.Variable `ebpf:"comm_deny_cnt"`
	DurationMs           *ebpf.Variable `ebpf:"duration_ms"`
	EntryUnused          *ebpf.Variable `ebpf:"entry_unused"`
	EventDataUnused      *ebpf.Variable `ebpf:"event_data_unused"`
	HasBpfGetFuncIp      *ebpf.Variable `ebpf:"has_bpf_get_func_ip"`
	KretOffset           *ebpf.Variable `ebpf:"kret_offset"`
	MaxDepth             *ebpf.Variable `ebpf:"max_depth"`
	MaxTraceBuf          *ebpf.Variable `ebpf:"max_trace_buf"`
	MaxTraceData         *ebpf.Variable `ebpf:"max_trace_data"`
	PidAllowCnt          *ebpf.Variable `ebpf:"pid_allow_cnt"`
	PidDenyCnt           *ebpf.Variable `ebpf:"pid_deny_cnt"`
	StartUnused          *ebpf.Variable `ebpf:"start_unused"`
	TraceConstantUnused  *ebpf.Variable `ebpf:"trace_constant_unused"`
	TraceDataFlagsUnused *ebpf.Variable `ebpf:"trace_data_flags_unused"`
	TraceUnused          *ebpf.Variable `ebpf:"trace_unused"`
	Verbose              *ebpf.Variable `ebpf:"verbose"`
}

// funcgraphPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFuncgraphObjects or ebpf.CollectionSpec.LoadAndAssign.
type funcgraphPrograms struct {
	Funcentry  *ebpf.Program `ebpf:"funcentry"`
	Funcret    *ebpf.Program `ebpf:"funcret"`
	HandleFork *ebpf.Program `ebpf:"handle_fork"`
	HandleFree *ebpf.Program `ebpf:"handle_free"`
}

func (p *funcgraphPrograms) Close() error {
	return _FuncgraphClose(
		p.Funcentry,
		p.Funcret,
		p.HandleFork,
		p.HandleFree,
	)
}

func _FuncgraphClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed funcgraph_arm64_bpfel.o
var _FuncgraphBytes []byte
