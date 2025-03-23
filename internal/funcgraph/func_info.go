package funcgraph

import (
	"bytes"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

const (
	MaxParaLen    = funcgraphTraceConstantPARA_LEN
	MaxTraceCount = int(funcgraphTraceConstantMAX_TRACES)
)

type Arg struct {
	Name   string
	Kind   ArgKind
	IdxOff uint32
	Size   int
	Typ    btf.Type
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

func (f *FuncInfo) ShowPara(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {

	if e.Id == 0 {
		for i := 0; i < MaxRegParas; i++ {
			fmt.Fprintf(dst, "%s=%#x ", RegToStr[i], e.Para[i])
		}
		return
	}

	for _, arg := range f.args {
		name := arg.Name
		typ := arg.Typ
		off := arg.IdxOff
		if arg.Kind == REG_PTR || arg.Kind == STACK_PTR {
			fmt.Fprintf(dst, "%s=ENOTSUP ", name)
			continue
		}
		if arg.Kind == STACK {
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
		fmt.Fprintf(dst, "%s=%#x", RetReg, e.Ret[0])
		return
	}

	off := 0
	if f.ret.Kind == RET_STACK {
		off = 8
	}
	sz, _ := btf.Sizeof(f.ret.Typ)
	if off+sz >= 128 {
		sz = 128 - int(off)
	}

	data := (*[128]byte)(unsafe.Pointer(&e.Ret[off]))
	opt.Reset(data[:sz], false, 0, true)
	opt.dumpDataByBTF("ret", f.ret.Typ, 0, 0, 0)
	dst.WriteString(opt.String())
}

func (f *FuncInfo) ShowTrace(e *FuncEvent, opt *dumpOption, dst *bytes.Buffer) {
	for idx, t := range f.trace {
		off := e.DataOff[idx]
		if off < 0 {
			msg := fmt.Sprintf("%*s%s = Error(%d)", int(10+e.Depth)*2, " ", t.name, off)
			dst.WriteString(msg)
			dst.WriteByte('\n')
			break
		}

		end := int32(e.DataLen)
		if idx+1 < len(f.trace) && e.DataOff[idx+1] >= 0 {
			end = e.DataOff[idx+1]
		}
		opt.Reset((*e.Data)[off:end], t.isStr, int(10+e.Depth), false)
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
			dst.WriteByte('\n')
			break
		}
		end := int32(e.DataLen)
		if idx+1 < len(f.trace) && e.DataOff[idx+1] >= 0 {
			end = e.DataOff[idx+1]
		}
		opt.Reset((*e.Data)[off:end], t.isStr, int(10+e.Depth), false)
		o, s := t.bitOff, t.bitSize
		opt.dumpDataByBTF(t.name, t.typ, 0, int(o), int(s))
		dst.WriteString(opt.String())
		dst.WriteByte('\n')
	}
}

func (f *FuncInfo) String() string {
	m := ""
	if f.Module != "" {
		m = f.Module + ":"
	}
	return m + f.Name
}

// func (f *FuncInfo) Format(fs fmt.State, verb rune) {
// 	if verb != 'v' && verb != 's' {
// 		fmt.Fprintf(fs, "{UNRECOGNIZED: %c}", verb)
// 		return
// 	}
// 	m := ""
// 	if f.Module != "" {
// 		m = f.Module + ":"
// 	}
// 	fmt.Fprintf(fs, "func:%q", m+f.Name)
// 	if verb == 's' {
// 		return
// 	}
// 	fmt.Fprintf(fs, " btfId %d", f.id)

// 	for _, arg := range f.args {
// 		loc := ""
// 		switch arg.Type {
// 		case REG:
// 			loc = fmt.Sprintf("reg+%d", arg.IdxOff)
// 		case STACK:
// 			loc = fmt.Sprintf("reg+%d", arg.IdxOff)
// 		}

// 	}
// }

func (f *FuncInfo) GenTraceData(dataExpr DataExpr) error {

	fn := f.Btfinfo
	// fmt.Printf("generate TraceData of %+v with %+v\n", dataExpr, fn)
	t := &TraceData{}
	var btfData btf.Type
	proto := fn.Type.(*btf.FuncProto)

	if dataExpr.First.Name != "" {
		if dataExpr.First.Name != "ret" {
			for idx, para := range proto.Params {
				if dataExpr.First.Name == para.Name {
					t.name = para.Name
					t.onEntry = true
					t.argKind = f.args[idx].Kind
					t.IdxOff = f.args[idx].IdxOff
					t.size = f.args[idx].Size
					t.typ = para.Type
					btfData = para.Type
					break
				}
			}
			if t.onEntry && len(f.retTrace) != 0 {
				return fmt.Errorf("entry expr must precede ret expr")
			}
		} else {
			t.name = "ret"
			t.onEntry = false
			t.argKind = f.ret.Kind
			t.IdxOff = f.ret.IdxOff
			t.size = f.ret.Size
			t.typ = proto.Return
			btfData = proto.Return
		}
		if t.name == "" {
			return fmt.Errorf("%v is not parameter of %s", dataExpr.First.Name, fn)
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

		t.onEntry = true
		maxIdx := len(f.trace)
		if len(f.retTrace) > 0 {
			t.onEntry = false
			maxIdx = len(f.retTrace)
		}

		if dataExpr.First.Addr.Base >= uint32(maxIdx) {
			return fmt.Errorf("parsing %s %q: base %d exceed range [0,%d)", f, dataExpr, dataExpr.First.Addr.Base, maxIdx)
		}
		if dataExpr.First.Addr.Index >= uint32(maxIdx) {
			return fmt.Errorf("parsing %s %q: index %d exceed range [0,%d)", f, dataExpr, dataExpr.First.Addr.Index, maxIdx)
		}
		if dataExpr.First.Addr.Scale != 0 {
			if dataExpr.First.Addr.Base == dataExpr.First.Addr.Index {
				return fmt.Errorf("parsing %s %q: base %d equal to index %d", f,
					dataExpr,
					dataExpr.First.Addr.Base,
					dataExpr.First.Addr.Index)
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
			return fmt.Errorf("parsing %s %q: type(%s) of base is not pointer", f, dataExpr, baseType)
		}

		t.argKind = ADDR

		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrBASE_LEN), uint32(funcgraphArgAddrBASE_SHIFT), base)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrINDEX_LEN), uint32(funcgraphArgAddrINDEX_SHIFT), index)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrSCALE_LEN), uint32(funcgraphArgAddrSCALE_SHIFT), scale)
		t.IdxOff |= writeBits(t.IdxOff, uint32(funcgraphArgAddrIMM_LEN), uint32(funcgraphArgAddrIMM_SHIFT), imm)
		t.size = 8

		spec, err := LoadBTFSpec(dataExpr.Typ.Moudle)
		if err != nil {
			return fmt.Errorf("loadbtfSpec: %s", err)
		}
		structPtr := &btf.Struct{}
		err = spec.TypeByName(dataExpr.Typ.Name, &structPtr)
		if err != nil {
			return fmt.Errorf("parsing %s %q: %s", f, dataExpr, err)
		}

		pointer := &btf.Pointer{
			Target: structPtr,
		}
		t.typ = pointer
		sz, err := btf.Sizeof(pointer)
		if err != nil {
			return fmt.Errorf("parsing %s %q: %s", f, dataExpr, err)
		}
		t.size = sz
		btfData = pointer
		// dataExpr.Typ.Name = ""
	}

	// fmt.Println(dataExpr.First, btfData)

	if err := genTraceDataByField(dataExpr.Fields, 0, btfData, t); err != nil {
		return fmt.Errorf("parsing %s %q: %w", f, dataExpr, err)
	}

	if dataExpr.Typ.Name != "" && t.argKind != ADDR {
		if _, ok := t.typ.(*btf.Pointer); ok {
			spec, err := LoadBTFSpec(dataExpr.Typ.Moudle)
			if err != nil {
				return fmt.Errorf("loadbtfSpec: %s", err)
			}
			structPtr := &btf.Struct{}
			err = spec.TypeByName(dataExpr.Typ.Name, &structPtr)
			if err != nil {
				return fmt.Errorf("parsing %s %q: %s", f, dataExpr, err)
			}

			pointer := &btf.Pointer{
				Target: structPtr,
			}
			t.typ = pointer
			t.name = fmt.Sprintf("(struct %s *)%s", dataExpr.Typ, t.name)

		} else {
			return fmt.Errorf("parsing %s %q: type cast only support pointer type: source type is %+v", f, dataExpr, t.typ)
		}
	}

	if dataExpr.Dereference {
		btfData := btf.UnderlyingType(t.typ)
		btfPointerData, ok := btfData.(*btf.Pointer)
		if !ok {
			return fmt.Errorf("parsing %s %q: can not dereference %s (non-pointer type)", f, dataExpr, btfData)
		}
		t.typ = btfPointerData.Target
		// t.Offsets = append(t.Offsets, 0)
		t.isDefer = true
		var err error
		t.size, err = btf.Sizeof(t.typ)
		if err != nil {
			return fmt.Errorf("parsing %s %q: %s", f, dataExpr, err)
		}
		t.name = "*" + t.name
	}

	if dataExpr.ShowString {
		t.isStr = true
		t.size = 1024
	}

	if arrTyp, ok := t.typ.(*btf.Array); ok {
		if intTyp, ok := arrTyp.Type.(*btf.Int); ok {
			if intTyp.Size == 1 && strings.Contains(intTyp.Name, "char") {
				t.isCharArray = true
			}
		}
	}

	if dataExpr.CompareInfo.Operator != "" {
		t.CmpOperator = convertCMPOp(dataExpr.CompareInfo.Operator)
		threshold := dataExpr.CompareInfo.Threshold

		if t.isStr || t.isCharArray {
			if target, err := threshold.ShowString(); err == nil {
				t.TargetStr = target
			} else {
				return fmt.Errorf("parsing %s %q: %s fail to get string: %s", f, dataExpr, threshold, err)
			}
		} else {
			if t.CmpOperator >= 7 {
				return fmt.Errorf("parsing %s %q: do not support \"~\" or \"!~\" opeartor", f, dataExpr)
			}
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
						return fmt.Errorf("parsing %s %q: %s fail to ParseInt: %s", f, dataExpr, threshold, err)
					}
				} else {
					t.Target, err = threshold.ShowUnsignNumber()
					if err != nil {
						return fmt.Errorf("parsing %s %q: %s fail to ParseUint: %s", f, dataExpr, threshold, err)
					}
				}

			case *btf.Pointer:
				var err error
				t.Target, err = threshold.ShowUnsignNumber()
				if err != nil {
					return fmt.Errorf("parsing %s %q: %s fail to ParseUint: %s", f, dataExpr, threshold, err)
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
					return fmt.Errorf("parsing %s %q: %s fail to get string: %s", f, dataExpr, threshold, err)
				}
			default:
				return fmt.Errorf("parsing %s %q: %s do not support compare now", f, dataExpr, typ)
			}
		}
	}
	// fmt.Printf("result: %+v\n\n", t)
	if t.onEntry {
		f.trace = append(f.trace, t)
	} else {
		f.retTrace = append(f.retTrace, t)
	}

	return nil
}

func mask(len uint32) uint32 {
	return (1 << len) - 1
}

// func readBits(value, len, shift uint32) uint32 {
// 	return (value >> shift) & mask(len)
// }

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

func genTraceDataByField(fs []Field, idx int, btfData btf.Type, t *TraceData) error {
	if idx >= len(fs) {
		return nil
	}
	btfData = btf.UnderlyingType(btfData)
	// fmt.Printf("analyse %+v with %+v\n", fs[idx], btfData)

	f := fs[idx]

	btfPointerData, ok := btfData.(*btf.Pointer)
	if !ok {
		return fmt.Errorf("%+v is not pointer type", btfData)
	}

	currStructType := btfPointerData.Target
	offset := uint16(0)

	fields := strings.Split(f.Name, ".")
	for _, name := range fields {
		currStructType = btf.UnderlyingType(currStructType)
		off, bitOff, bitSize, typ, found := caculateOffset(name, currStructType)
		if !found {
			return fmt.Errorf("%+v is not field of %s", name, currStructType)
		}
		currStructType = typ
		offset += uint16(off)
		t.bitOff = uint8(bitOff)
		t.bitSize = uint8(bitSize)
		// t.BitOff = bitOff
		// t.BitSize = bitSize
	}

	if index, err := f.Index.ShowSignNumber(); err == nil {
		currStructType = btf.UnderlyingType(currStructType)
		if typ, ok := currStructType.(*btf.Array); ok {
			if index < 0 {
				return fmt.Errorf("array index %+v must >= 0", index)
			}
			if uint32(index) >= typ.Nelems {
				return fmt.Errorf("array index %+v should below %+v", index, typ.Nelems)
			}
			currStructType = typ.Type
			if sz, err := btf.Sizeof(currStructType); err == nil {
				f.Name += fmt.Sprintf("[%d]", index)
				offset += uint16(sz) * uint16(index)
			} else {
				return fmt.Errorf("%+v cannot get size: %s", currStructType, err)
			}
		} else {
			return fmt.Errorf("%+v is not array", currStructType)
		}
	}

	t.typ = currStructType
	t.offsets = append(t.offsets, offset)
	if sz, err := btf.Sizeof(currStructType); err == nil {
		t.size = sz
	} else {
		return fmt.Errorf("%+v cannot get size: %s", currStructType, err)
	}

	t.name += "->" + f.Name

	return genTraceDataByField(fs, idx+1, currStructType, t)
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
	case "~":
		return 7
	case "!~":
		return 8
	}
	return 0
}
