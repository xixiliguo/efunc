package funcgraph

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/cilium/ebpf/btf"
)

const (
	MaxParaLen      = funcgraphTraceConstantPARA_LEN
	MaxLenPerTrace  = int(funcgraphTraceConstantMAX_TRACE_DATA)
	MaxTraceDataLen = int(funcgraphTraceConstantMAX_TRACE_BUF)
	MaxTraceCount   = int(funcgraphTraceConstantMAX_TRACES)
)

// support module symbol later
type FuncExpr struct {
	Module string     `parser:"(@Ident Colon)?"`
	Name   string     `parser:"@Ident"`
	Datas  []DataExpr `parser:"(LeftEdge@@(Whitespace? Separator Whitespace? @@)*RightEdge)?"`
}

type DataExpr struct {
	Dereference bool     `parser:"@DereferenceOperator?"`
	Typ         CastType `parser:"(LeftEdge Struct Whitespace @@ Whitespace DereferenceOperator RightEdge)?"`
	First       Primary  `parser:"@@"`
	Fields      []Field  `parser:"@@*"`
	SohwString  bool     `parser:"@ShowString?"`
	CompareInfo Compare  `parser:"@@?"`
}

type CastType struct {
	Moudle string `parser:"(@Ident Colon)?"`
	Name   string `parser:"@Ident"`
}

type Primary struct {
	Name string `parser:"@Ident"`
	Addr Addr   `parser:"| LeftEdge @@ RightEdge"`
}

type Addr struct {
	Base  uint32 `parser:"@Number"`
	Index uint32 `parser:"Separator @Number"`
	Scale int32  `parser:"Separator @Number"`
	Imm   int32  `parser:"Separator @Number"`
}

type Field struct {
	Name string `parser:"ArrowOperator@(Ident (Period Ident)*)"`
}

type Compare struct {
	Operator  string `parser:"Whitespace@Operator"`
	Threshold Value  `parser:"Whitespace@(String|Number)"`
}

type Value struct {
	s string
}

func (v *Value) Capture(values []string) error {
	v.s = values[0]
	return nil
}

func (v Value) String() string {
	return v.s
}

func (v Value) ShowString() (string, error) {
	if len(v.s) >= 3 && v.s[0] == '"' && v.s[len(v.s)-1] == '"' {
		return v.s[1 : len(v.s)-1], nil
	}
	return "", errors.New("should not empty string")
}

func (v Value) ShowSignNumber() (int64, error) {
	return strconv.ParseInt(v.s, 0, 64)
}

func (v Value) ShowUnsignNumber() (uint64, error) {
	return strconv.ParseUint(v.s, 0, 64)
}

type Arg struct {
	Type   ArgType
	IdxOff uint32
	Size   int
}

type FuncInfo struct {
	IsEntry bool
	Symbol
	id       btf.TypeID
	Btfinfo  *btf.Func
	args     []Arg
	ret      Arg
	trace    []*TraceData
	retTrace []*TraceData
}

func idxInReg(idx int) bool {
	if runtime.GOARCH == "amd64" {
		return idx < 6
	}
	return idx < 8
}

func (f *FuncInfo) InitArgsRet() {

	proto := f.Btfinfo.Type.(*btf.FuncProto)
	regIdx := 0
	if sz, _ := btf.Sizeof(proto.Return); sz > 16 {
		regIdx = 1
	}
	stackOff := 1

	for _, p := range proto.Params {
		arg := Arg{}
		sz, _ := btf.Sizeof(p.Type)
		if sz <= 8 && idxInReg(regIdx) {
			arg.Type = REG
			arg.IdxOff = uint32(regIdx)
			regIdx += 1
		} else if sz <= 16 && idxInReg(regIdx) && idxInReg(regIdx+1) {
			arg.Type = REG
			arg.IdxOff = uint32(regIdx)
			regIdx += 2
		} else {
			arg.Type = STACK
			arg.IdxOff = uint32(stackOff)
			stackOff += (sz + 7) / 8
		}
		arg.Size = sz
		f.args = append(f.args, arg)
	}

	sz, _ := btf.Sizeof(proto.Return)
	if sz <= 16 {
		f.ret = Arg{
			RET_REG,
			0,
			sz,
		}
	} else {
		f.ret = Arg{
			STACK,
			0,
			sz,
		}
	}
}

func (f *FuncInfo) ShowPara(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {

	if e.Id == 0 {
		fmt.Fprintf(dst, "%#x %#x %#x", 1, 2, 3)
		return
	}

	proto := f.Btfinfo.Type.(*btf.FuncProto)
	for idx, arg := range f.args {
		name := proto.Params[idx].Name
		typ := proto.Params[idx].Type
		off := arg.IdxOff
		if arg.Type == STACK {
			off = arg.IdxOff + 8
		}
		if off >= uint32(MaxParaLen) {
			continue
		}
		sz, _ := btf.Sizeof(typ)
		if off+uint32(sz) >= 128 {
			sz = 128 - int(off)
		}
		// fmt.Printf("xxx %+v %+v %+v %+v %+v\n", funcInfo.Name, name, arg, e.Para, off)
		data := (*[128]byte)(unsafe.Pointer(&e.Para[off]))
		opt.Reset(data[:sz], false, 0, true)
		opt.dumpDataByBTF(name, typ, 0, 0, 0)
		dst.WriteString(opt.String())
		dst.WriteString(" ")
	}
}

func (f *FuncInfo) ShowRet(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {
	if e.Id == 0 {
		fmt.Fprintf(dst, "%#x", e.Ret)
		return
	}

	proto := f.Btfinfo.Type.(*btf.FuncProto)
	typ := proto.Return

	sz, _ := btf.Sizeof(typ)
	if sz >= 16 {
		sz = 16
	}

	data := (*[16]byte)(unsafe.Pointer(&e.Ret[0]))
	opt.Reset(data[:sz], false, 0, true)
	opt.dumpDataByBTF("ret", typ, 0, 0, 0)
	dst.WriteString(opt.String())
}

func (f *FuncInfo) ShowTrace(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {
	for idx, t := range f.trace {
		off := e.DataOff[idx]
		if off < 0 {
			msg := fmt.Sprintf("%*s%s = Error(%d)", int(10+e.Depth)*2, " ", t.name, off)
			dst.WriteString(msg)
			break
		}
		sz := t.size
		if sz > MaxLenPerTrace {
			sz = MaxLenPerTrace
		}
		if int(off)+sz >= MaxTraceDataLen {
			sz = MaxTraceDataLen - int(off)
		}
		opt.Reset(e.Data[off:int(off)+sz], t.isStr, int(10+e.Depth), false)
		o, s := t.bitOff, t.bitSize
		opt.dumpDataByBTF(t.name, t.typ, 0, int(o), int(s))
		dst.WriteString(opt.String())
		dst.WriteByte('\n')
	}
}

func (f *FuncInfo) ShowRetTrace(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {
	for idx, t := range f.retTrace {
		off := e.DataOff[idx]
		if off < 0 {
			msg := fmt.Sprintf("%*s%s = Error(%d)", int(10+e.Depth)*2, " ", t.name, off)
			dst.WriteString(msg)
			break
		}
		sz := t.size
		if sz > 1024 {
			sz = 1024
		}
		if int(off)+sz >= MaxTraceDataLen {
			sz = MaxTraceDataLen - int(off)
		}
		opt.Reset(e.Data[off:int(off)+sz], t.isStr, int(10+e.Depth), false)
		o, s := t.bitOff, t.bitSize
		opt.dumpDataByBTF(t.name, t.typ, 0, int(o), int(s))
		dst.WriteString(opt.String())
		dst.WriteByte('\n')
	}
}

func (f *FuncInfo) GenTraceData(dataExpr DataExpr) {

	fn := f.Btfinfo
	fmt.Printf("generate TraceData of %+v with %+v\n", dataExpr, fn)
	t := &TraceData{}
	var btfData btf.Type
	proto := fn.Type.(*btf.FuncProto)

	if dataExpr.First.Name != "" {
		if dataExpr.First.Name != "ret" {
			for idx, para := range proto.Params {
				if dataExpr.First.Name == para.Name {
					t.name = para.Name
					t.onEntry = true
					t.argType = f.args[idx].Type
					t.IdxOff = f.args[idx].IdxOff
					t.size = f.args[idx].Size
					t.typ = para.Type
					btfData = para.Type
					break
				}
			}
			if t.onEntry && len(f.retTrace) > 1 {
				fmt.Printf("entry expr must be before ret expr: %+v\n", t)
				os.Exit(1)
			}
		} else {
			t.name = "ret"
			t.onEntry = false
			t.argType = f.ret.Type
			t.IdxOff = f.ret.IdxOff
			t.size = f.ret.Size
			t.typ = proto.Return
			btfData = proto.Return
		}

	} else {
		t.name = fmt.Sprintf("(struct %s *)(%d,%d,%d,%d)", dataExpr.Typ.Name,
			dataExpr.First.Addr.Base,
			dataExpr.First.Addr.Index,
			dataExpr.First.Addr.Scale,
			dataExpr.First.Addr.Imm)
		if len(dataExpr.Fields) != 0 {
			t.name = "(" + t.name + ")"
		}
		// t.Arg = uint64(ARG_ADDR) << 60

		t.onEntry = true
		maxIdx := len(f.trace)
		if len(f.retTrace) > 0 {
			t.onEntry = false
			maxIdx = len(f.retTrace)
		}

		if dataExpr.First.Addr.Base >= uint32(maxIdx) {
			fmt.Printf("%+v base idx %d exceed range: %+v \n", t, dataExpr.First.Addr.Base, maxIdx)
			os.Exit(1)
		}
		if dataExpr.First.Addr.Index >= uint32(maxIdx) {
			fmt.Printf("%+v index idx %d exceed range: %+v \n", t, dataExpr.First.Addr.Index, maxIdx)
			os.Exit(1)
		}
		if dataExpr.First.Addr.Scale != 0 {
			if dataExpr.First.Addr.Base == dataExpr.First.Addr.Index {
				fmt.Printf("%+v base %d should not the same with index %+v \n", t, dataExpr.First.Addr.Base, dataExpr.First.Addr.Index)
				os.Exit(1)
			}
		}

		base := uint32(dataExpr.First.Addr.Base)
		index := uint32(dataExpr.First.Addr.Index)
		scale := uint32(dataExpr.First.Addr.Scale)
		imm := uint32(dataExpr.First.Addr.Imm)
		var baseType btf.Type
		if t.onEntry {
			baseType = f.trace[base].typ
		} else {
			baseType = f.retTrace[base].typ
		}
		if _, ok := baseType.(*btf.Pointer); !ok {
			fmt.Printf("Base type is not pointer\n")
			os.Exit(1)
		}

		//5 + 5 + 14 + 16
		// addr := uint64(0)
		// addr |= uint64(base) << 35
		// addr |= uint64(index) << 30
		// addr |= uint64(dataExpr.First.Addr.Scale) << 16
		// addr |= uint64(dataExpr.First.Addr.Imm)
		// fmt.Printf("abc %+v  b %+v i %+v s %+v, i %+v\n", addr, base, index, dataExpr.First.Addr.Scale, dataExpr.First.Addr.Imm)
		// t.Arg |= uint64(addr) << 16

		t.argType = ADDR

		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrBASE_LEN), uint32(funcgraphArgAddrBASE_SHIFT), base)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrINDEX_LEN), uint32(funcgraphArgAddrINDEX_SHIFT), index)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrSCALE_LEN), uint32(funcgraphArgAddrSCALE_SHIFT), scale)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrIMM_LEN), uint32(funcgraphArgAddrIMM_SHIFT), imm)
		t.size = 8
		fmt.Printf("abc   b %+v i %+v s %+v, i %+v\n", base, index, dataExpr.First.Addr.Scale, dataExpr.First.Addr.Imm)
		// t.onEntry = true
		spec, err := LoadbtfSpec(dataExpr.Typ.Moudle)
		if err != nil {
			fmt.Printf("loadbtfSpec: %s\n", err)
			os.Exit(1)
		}
		structPtr := &btf.Struct{}
		err = spec.TypeByName(dataExpr.Typ.Name, &structPtr)
		if err != nil {
			fmt.Printf("TypeByName %s: %s\n", dataExpr.Typ, err)
			os.Exit(1)
		}

		pointer := &btf.Pointer{
			Target: structPtr,
		}
		t.typ = pointer
		sz, _ := btf.Sizeof(pointer)
		t.size = sz
		btfData = pointer
		dataExpr.Typ.Name = ""
	}

	fmt.Println(dataExpr.First, btfData)

	if btfData != nil {

		genTraceDataByField(dataExpr.Fields, 0, btfData, t)

		if dataExpr.Typ.Name != "" {
			if _, ok := t.typ.(*btf.Pointer); ok {
				spec, err := LoadbtfSpec(dataExpr.Typ.Moudle)
				if err != nil {
					fmt.Printf("loadbtfSpec: %s\n", err)
					os.Exit(1)
				}
				structPtr := &btf.Struct{}
				err = spec.TypeByName(dataExpr.Typ.Name, &structPtr)
				if err != nil {
					fmt.Printf("TypeByName %s: %s\n", dataExpr.Typ, err)
					os.Exit(1)
				}

				pointer := &btf.Pointer{
					Target: structPtr,
				}
				t.typ = pointer
				t.name = fmt.Sprintf("(struct %s *)%s", dataExpr.Typ, t.name)

			} else {
				fmt.Printf("type cast only support pointer type: source type is %+v\n", t.typ)
				os.Exit(1)
			}
		}

		if dataExpr.Dereference {
			btfData := btf.UnderlyingType(t.typ)
			btfPointerData, ok := btfData.(*btf.Pointer)
			if !ok {
				fmt.Printf("%+v is not pointer type\n", btfData)
				os.Exit(1)
			}
			t.typ = btfPointerData.Target
			// t.Offsets = append(t.Offsets, 0)
			t.isDefer = true
			if sz, err := btf.Sizeof(t.typ); err == nil {
				t.size = sz
			} else {
				fmt.Printf("%+v cannot get size: %s\n", t.typ, err)
				os.Exit(1)
			}
			t.name = "*" + t.name
		}

	} else {
		fmt.Printf("%+v is not parameter of %s\n", dataExpr.First, fn)
		os.Exit(1)
	}
	if dataExpr.SohwString {
		t.isStr = true
		t.size = 1024
	}

	if dataExpr.CompareInfo.Operator != "" {
		t.CmpOperator = convertCMPOp(dataExpr.CompareInfo.Operator)
		threshold := dataExpr.CompareInfo.Threshold

		if t.isStr {
			if target, err := threshold.ShowString(); err == nil {
				tb := (*[8]byte)(unsafe.Pointer(&t.Target))
				copy(tb[:], target)
			} else {
				fmt.Printf("%s fail to get string: %s\n", threshold, err)
				os.Exit(1)
			}
		} else {
			switch typ := btf.UnderlyingType(t.typ).(type) {
			case *btf.Int:
				if typ.Encoding == btf.Signed {
					t.isSign = true
				}
				var err error
				if t.isSign {
					n, err := threshold.ShowSignNumber()
					t.Target = uint64(n)
					if err != nil {
						fmt.Printf("%s fail to ParseInt: %s\n", threshold, err)
						os.Exit(1)
					}
				} else {
					t.Target, err = threshold.ShowUnsignNumber()
					if err != nil {
						fmt.Printf("%s fail to ParseUint: %s\n", threshold, err)
						os.Exit(1)
					}
				}

			case *btf.Pointer:
				var err error
				t.Target, err = threshold.ShowUnsignNumber()
				if err != nil {
					fmt.Printf("%s fail to ParseUint: %s\n", threshold, err)
					os.Exit(1)
				}
			case *btf.Enum:
				if typ.Signed {
					t.isSign = true
				}
				if target, err := threshold.ShowString(); err == nil {
					for i := 0; i < len(typ.Values); i++ {
						if target == typ.Values[i].Name {
							t.Target = typ.Values[i].Value
						}
					}
				} else {
					fmt.Printf("%s fail to get string: %s\n", threshold, err)
					os.Exit(1)
				}
			default:
				fmt.Printf("%+v do not support cmp now\n", typ)
				os.Exit(1)
			}
		}
	}
	fmt.Printf("result: %+v\n\n", t)
	if t.onEntry {
		f.trace = append(f.trace, t)
	} else {
		f.retTrace = append(f.retTrace, t)
	}

	return
}

func mask(len uint32) uint32 {
	return (1 << len) - 1
}

func readBits(value, len, shift uint32) uint32 {
	return (value >> shift) & mask(len)
}

func writeBits(value, len, shift, new uint32) uint32 {
	value &^= mask(len) << shift
	value |= (new & mask(len)) << shift
	return value
}

func caculateOffset(name string, btfData btf.Type) (uint32, uint32, uint32, btf.Type, bool) {
	switch typ := btf.UnderlyingType(btfData).(type) {
	case *btf.Union:
		for _, mem := range typ.Members {
			if mem.Name == "" {
				off, bitOff, bitSize, typ, found := caculateOffset(name, mem.Type)
				if found {
					return mem.Offset.Bytes() + off, bitOff, bitSize, typ, found
				}
			} else if mem.Name == name {
				offset := uint32(mem.Offset / 8)
				bitOff := uint32(mem.Offset % 8)
				bitSize := uint32(mem.BitfieldSize)
				return offset, bitOff, bitSize, mem.Type, true
			}
		}
		return 0, 0, 0, nil, false
	case *btf.Struct:
		for _, mem := range typ.Members {
			if mem.Name == "" {
				off, bitOff, bitSize, typ, found := caculateOffset(name, mem.Type)
				if found {
					return mem.Offset.Bytes() + off, bitOff, bitSize, typ, found
				}
			} else if mem.Name == name {
				offset := uint32(mem.Offset / 8)
				bitOff := uint32(mem.Offset % 8)
				bitSize := uint32(mem.BitfieldSize)
				return offset, bitOff, bitSize, mem.Type, true
			}
		}
		return 0, 0, 0, nil, false
	default:
		// fmt.Printf("%+v is not struct/union when caculating field %s\n", typ, name)
		return 0, 0, 0, nil, false
	}
}

func genTraceDataByField(fs []Field, idx int, btfData btf.Type, t *TraceData) {
	if idx >= len(fs) {
		return
	}
	btfData = btf.UnderlyingType(btfData)
	fmt.Printf("analyse %+v with %+v\n", fs[idx], btfData)

	f := fs[idx]

	btfPointerData, ok := btfData.(*btf.Pointer)
	if !ok {
		fmt.Printf("%+v is not pointer type\n", btfData)
		os.Exit(1)
	}

	currStructType := btfPointerData.Target
	offset := uint16(0)

	fields := strings.Split(f.Name, ".")
	for _, name := range fields {
		currStructType = btf.UnderlyingType(currStructType)
		off, bitOff, bitSize, typ, found := caculateOffset(name, currStructType)
		if !found {
			fmt.Printf("%+v is not field of %+v\n", name, currStructType)
			os.Exit(1)
		}
		currStructType = typ
		offset += uint16(off)
		t.bitOff = uint8(bitOff)
		t.bitSize = uint8(bitSize)
		// t.BitOff = bitOff
		// t.BitSize = bitSize
	}

	t.typ = currStructType
	t.offsets = append(t.offsets, offset)
	if sz, err := btf.Sizeof(currStructType); err == nil {
		t.size = sz
	} else {
		fmt.Printf("%+v cannot get size: %s\n", currStructType, err)
		os.Exit(1)
	}

	t.name += "->" + f.Name

	genTraceDataByField(fs, idx+1, currStructType, t)

}

var funcParserFunc = sync.OnceValue[*participle.Parser[FuncExpr]](func() *participle.Parser[FuncExpr] {
	clexer := lexer.MustSimple([]lexer.SimpleRule{
		{Name: "DereferenceOperator", Pattern: `\*`},
		{Name: "Struct", Pattern: `struct`},
		{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z_0-9]*`},
		{Name: "ArrowOperator", Pattern: `->`},
		{Name: "ShowString", Pattern: `:str`},
		{Name: "Whitespace", Pattern: `[ \t]+`},
		{Name: "Colon", Pattern: `:`},
		{Name: "Period", Pattern: `\.`},
		{Name: "LeftEdge", Pattern: `\(`},
		{Name: "RightEdge", Pattern: `\)`},
		{Name: "Separator", Pattern: `,`},
		{Name: "Operator", Pattern: `>=|>|==|!=|<=|<`},
		{Name: "Number", Pattern: `([-+]?0x[a-zA-Z_0-9]+)|([-+]?\d+)`},
		{Name: "String", Pattern: `".*"`},
	})

	parser, _ := participle.Build[FuncExpr](participle.Lexer(clexer))
	return parser
})

func ParseFuncWithPara(s string) (*FuncExpr, error) {
	p := funcParserFunc()
	return p.ParseString("", s)
}

func ShowBtfFunc(fn *btf.Func) (s string) {
	if proto, ok := fn.Type.(*btf.FuncProto); ok {
		s = typToString(proto.Return)
		s += fmt.Sprintf(" %s(", fn.Name)
		paras := []string{}
		for _, para := range proto.Params {
			paras = append(paras, typToString(para.Type)+" "+para.Name)
		}
		s += strings.Join(paras, ", ")
		s += ")"
	}
	return s
}

func typToString(typ btf.Type) string {

	re := ""
	typ = btf.UnderlyingType(typ)
	switch t := typ.(type) {
	case *btf.Int:
		if t.Name == "_Bool" {
			return "bool"
		}
		re = t.Name
	case *btf.Struct:
		re = "struct"
		if t.Name != "" {
			re += " " + t.Name
		}
	case *btf.Void:
		re = "void"
	case *btf.FuncProto:
		s := typToString(t.Return)
		s += " (*func)("
		paras := []string{}
		for _, para := range t.Params {
			paras = append(paras, typToString(para.Type))
		}
		s += strings.Join(paras, ", ")
		s += ")"
		re = s
	case *btf.Pointer:
		tt := btf.UnderlyingType(t.Target)
		if pp, ok := tt.(*btf.Pointer); ok {
			return typToString(pp.Target) + " **"
		}
		if pp, ok := tt.(*btf.FuncProto); ok {
			return typToString(pp)
		}
		re = typToString(t.Target) + " *"
	case *btf.Array:
		re = fmt.Sprintf("%s[%d]", typToString(t.Type), t.Nelems)
	case *btf.Fwd:
		re = fmt.Sprintf("%s %s", t.Kind, t.Name)
	case *btf.Union:
		re = "union"
		if t.Name != "" {
			re += " " + t.Name
		}
	case *btf.Enum:
		re = "enum"
		if t.Name != "" {
			re += " " + t.Name
		}
	default:
		re = fmt.Sprintf("don't know how to toString Type %v", typ)
	}
	return re
}

func convertCMPOp(op string) uint8 {
	switch op {
	case "==":
		return 1
	case "!=":
		return 2
	case ">":
		return 3
	case ">=":
		return 4
	case "<":
		return 5
	case "<=":
		return 6
	}
	return 0
}
