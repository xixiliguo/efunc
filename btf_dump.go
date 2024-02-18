package main

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

func toString(typ btf.Type) string {
	typ = btf.UnderlyingType(typ)
	switch t := typ.(type) {
	case *btf.Int:
		if t.Name == "_Bool" {
			return "bool"
		}
		return t.Name
	case *btf.Struct:
		return "struct " + t.Name
	case *btf.Void:
		return "void"
	case *btf.FuncProto:
		s := toString(t.Return)
		s += " (*func)("
		paras := []string{}
		for _, para := range t.Params {
			paras = append(paras, toString(para.Type))
		}
		s += strings.Join(paras, ", ")
		s += ")"
		return s
	case *btf.Pointer:
		tt := btf.UnderlyingType(t.Target)
		if pp, ok := tt.(*btf.Pointer); ok {
			return toString(pp.Target) + " **"
		}
		if pp, ok := tt.(*btf.FuncProto); ok {
			return toString(pp)
		}
		return toString(t.Target) + " *"
	case *btf.Array:
		return fmt.Sprintf("%s[%d]", toString(t.Type), t.Nelems)
	case *btf.Fwd:
		return fmt.Sprintf("%s %s", t.Kind, t.Name)
	case *btf.Union:
		return "union " + t.Name
	case *btf.Enum:
		return "enum " + t.Name
	}
	return fmt.Sprintf("don't know how to toString Type %v", typ)
}

type dumpOption struct {
	data    []byte
	isStr   bool
	level   int
	offset  int
	bitOff  int
	bitSize int
	ksyms   *KSymCache
	s       *strings.Builder
}

func dumpDataByBTF(opt dumpOption, name string, typ btf.Type) bool {

	offset := opt.offset
	level := opt.level
	data := opt.data
	s := opt.s

	space := strings.Repeat("  ", level)
	if sz, err := btf.Sizeof(typ); err != nil {
		fmt.Fprintf(s, "%sdon't know %s size: %s\n", space, name, err)
		return false
	} else {
		if offset != 0 && offset+sz > len(data) {
			fmt.Fprintf(s, "%s/* only show first %d bytes */\n", space, offset)
			return false
		}
	}

	prefix := name + " ="
	if name == "" {
		prefix = ""
	}

	if opt.isStr {
		fmt.Fprintf(s, "%s%s %s\n", space, prefix, unix.ByteSliceToString(data[offset:]))

		return true
	}

	typ = btf.UnderlyingType(typ)
	switch t := typ.(type) {
	case *btf.Union:
		fmt.Fprintf(s, "%s%s (%s) {\n", space, prefix, toString(t))
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8

			childOpt := dumpOption{
				data:    data,
				isStr:   false,
				level:   level + 1,
				offset:  offset + int(memOff),
				bitOff:  int(memBitOff),
				bitSize: int(mem.BitfieldSize),
				ksyms:   opt.ksyms,
				s:       s,
			}
			result := dumpDataByBTF(childOpt, mem.Name, mem.Type)
			if !result {
				return false
			}
		}
		fmt.Fprintf(s, "%s}\n", space)
	case *btf.Struct:
		fmt.Fprintf(s, "%s%s (%s) {\n", space, prefix, toString(t))
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			childOpt := dumpOption{
				data:    data,
				isStr:   false,
				level:   level + 1,
				offset:  offset + int(memOff),
				bitOff:  int(memBitOff),
				bitSize: int(mem.BitfieldSize),
				ksyms:   opt.ksyms,
				s:       s,
			}
			result := dumpDataByBTF(childOpt, mem.Name, mem.Type)
			if !result {
				return false
			}
		}
		fmt.Fprintf(s, "%s}\n", space)
	case *btf.Array:
		// special case for char[]
		sz, _ := btf.Sizeof(t.Type)
		if end := offset + int(t.Nelems); sz == 1 && end <= len(data) {
			fmt.Fprintf(s, "%s%s (%s[%d)) %q\n", space, prefix, toString(t.Type), t.Nelems, data[offset:offset+int(t.Nelems)])
			return true
		}
		fmt.Fprintf(s, "%s%s (%s[%d)) {\n", space, prefix, toString(t.Type), t.Nelems)

		for i := 0; i < int(t.Nelems); i++ {
			childOpt := dumpOption{
				data:    data,
				isStr:   false,
				level:   level + 1,
				offset:  offset + i*sz,
				bitOff:  0,
				bitSize: 0,
				ksyms:   opt.ksyms,
				s:       s,
			}
			result := dumpDataByBTF(childOpt, "", t.Type)
			if !result {
				return false
			}
		}
		fmt.Fprintf(s, "%s}\n", space)
	case *btf.Int:
		var msg string
		switch {
		case t.Encoding == btf.Signed && t.Size == 1:
			d := *(*int8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Sprintf("%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Signed && t.Size == 2:
			d := *(*int16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Signed && t.Size == 4:
			d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Signed && t.Size == 8:
			d := *(*int64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 1:
			d := *(*uint8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Sprintf("%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Unsigned && t.Size == 2:
			d := *(*uint16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 4:
			d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 8:
			d := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Char:
			msg = fmt.Sprintf("%#x", data[offset])
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Sprintf("%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Bool:
			msg = fmt.Sprintf("%t", data[offset] != 0)
		default:
			msg = fmt.Sprintf("unkown(%v)", t)
		}
		fmt.Fprintf(s, "%s%s (%s)%s\n", space, prefix, toString(t), msg)
	case *btf.Pointer:
		p := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))

		symInfo := ""
		if p != 0 {
			if sym := opt.ksyms.SymbolByAddr(p, true); sym.Name != "" {
				symInfo = "<" + sym.Name + ">"
			}
		}
		fmt.Fprintf(s, "%s%s (%s)%#x %s\n", space, prefix, toString(t), p, symInfo)
	case *btf.Enum:
		if t.Signed {
			d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					fmt.Fprintf(s, "%s%s(%s) %s\n", space, prefix, toString(t), value.Name)

				}
			}
		} else {
			d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					fmt.Fprintf(s, "%s%s(%s) %s\n", space, prefix, toString(t), value.Name)

				}
			}
		}
	default:
		fmt.Fprintf(s, "%s%s don't know how to print %v\n", space, prefix, t)
	}
	return true
}
