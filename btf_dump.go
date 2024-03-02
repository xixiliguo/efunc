package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

type dumpOption struct {
	data           []byte
	isStr          bool
	level          int
	offset         int
	bitOff         int
	bitSize        int
	ksyms          *KSymCache
	s              *strings.Builder
	spaceCache     [1024]byte
	prefixCache    map[string]string
	typStringCache map[btf.Type]string
}

func NewDumpOption() (*dumpOption, error) {
	k, err := NewKSymCache()
	if err != nil {
		return nil, err
	}
	d := dumpOption{
		data:           nil,
		isStr:          false,
		level:          0,
		offset:         0,
		bitOff:         0,
		bitSize:        0,
		ksyms:          &k,
		s:              &strings.Builder{},
		prefixCache:    make(map[string]string),
		typStringCache: make(map[btf.Type]string),
	}
	for i := 0; i < len(d.spaceCache); i++ {
		d.spaceCache[i] = ' '
	}
	d.prefixCache[""] = ""

	return &d, nil
}

func (opt *dumpOption) Reset(data []byte, isStr bool, level int) {
	opt.data = data
	opt.isStr = isStr
	opt.level = level
	opt.offset = 0
	opt.bitOff = 0
	opt.bitSize = 0
	opt.s.Reset()
	opt.s.Grow(len(data) * 2)
}

func (opt *dumpOption) String() string {
	return opt.s.String()
}

func (opt *dumpOption) toString(typ btf.Type) string {
	if s, ok := opt.typStringCache[typ]; ok {
		return s
	}
	re := typToString(typ)
	opt.typStringCache[typ] = re
	return re
}

func (opt *dumpOption) WriteStrings(ss ...string) {
	for i := 0; i < len(ss); i++ {
		opt.s.WriteString(ss[i])
	}
}

func (opt *dumpOption) dumpDataByBTF(name string, typ btf.Type) bool {

	offset := opt.offset
	level := opt.level
	data := opt.data
	s := opt.s

	// space := strings.Repeat("  ", level)
	space := toString(opt.spaceCache[:2*level])
	if sz, err := btf.Sizeof(typ); err != nil {
		opt.WriteStrings(space, "don't know ", name, " size: ", err.Error(), "\n")
		// fmt.Fprintf(s, "%sdon't know %s size: %s\n", space, name, err)
		return false
	} else {
		if offset != 0 && offset+sz > len(data) {
			cnt := strconv.FormatInt(int64(offset), 10)
			opt.WriteStrings(space, "/* only show first ", cnt, " bytes */\n")
			// fmt.Fprintf(s, "%s/* only show first %d bytes */\n", space, offset)
			return false
		}
	}

	prefix := ""
	if r, ok := opt.prefixCache[name]; ok {
		prefix = r
	} else {
		opt.prefixCache[name] = name + " ="
		prefix = opt.prefixCache[name]
	}

	if opt.isStr {
		re := unix.ByteSliceToString(data[offset:])
		opt.WriteStrings(space, prefix, re, "\n")
		// fmt.Fprintf(s, "%s%s %s\n", space, prefix)
		return true
	}

	typ = btf.UnderlyingType(typ)
	switch t := typ.(type) {
	case *btf.Union:
		opt.WriteStrings(space, prefix, " (", opt.toString(t), ") {\n")
		// opt.s.Write(space)
		// opt.s.Write([]byte(prefix))
		// opt.s.WriteString(" (")
		// opt.s.WriteString(opt.toString(t))
		// opt.s.WriteString(") {\n")
		// fmt.Fprintf(s, "%s%s (%s) {\n", space, prefix, toString(t))
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8

			// childOpt := dumpOption{
			// 	data:    data,
			// 	isStr:   false,
			// 	level:   level + 1,
			// 	offset:  offset + int(memOff),
			// 	bitOff:  int(memBitOff),
			// 	bitSize: int(mem.BitfieldSize),
			// 	ksyms:   opt.ksyms,
			// 	s:       s,
			// }
			opt.level++
			opt.offset += int(memOff)
			opt.bitOff = int(memBitOff)
			opt.bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type)
			opt.level--
			opt.offset -= int(memOff)
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")
		// opt.s.WriteString(space)
		// opt.s.WriteString("}\n")
		// fmt.Fprintf(s, "%s}\n", space)
	case *btf.Struct:
		opt.WriteStrings(space, prefix, " (", opt.toString(t), ") {\n")
		// opt.s.Write(space)
		// opt.s.Write([]byte(prefix))
		// opt.s.WriteString(" (")
		// opt.s.WriteString(opt.toString(t))
		// opt.s.WriteString(") {\n")
		// fmt.Fprintf(s, "%s%s (%s) {\n", space, prefix, toString(t))
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			// childOpt := dumpOption{
			// 	data:    data,
			// 	isStr:   false,
			// 	level:   level + 1,
			// 	offset:  offset + int(memOff),
			// 	bitOff:  int(memBitOff),
			// 	bitSize: int(mem.BitfieldSize),
			// 	ksyms:   opt.ksyms,
			// 	s:       s,
			// }
			opt.level++
			opt.offset += int(memOff)
			opt.bitOff = int(memBitOff)
			opt.bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type)
			opt.level--
			opt.offset -= int(memOff)
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")
		// opt.s.WriteString(space)
		// opt.s.WriteString("}\n")
		// fmt.Fprintf(s, "%s}\n", space)
	case *btf.Array:
		// special case for char[]
		sz, _ := btf.Sizeof(t.Type)
		if end := offset + int(t.Nelems); sz == 1 && end <= len(data) {
			// opt.s.WriteString(space)
			// opt.s.Write([]byte(prefix))
			// opt.s.WriteString(" (")
			// opt.s.WriteString(opt.toString(t.Type))
			// opt.s.WriteString("[")
			n := strconv.FormatUint(uint64(t.Nelems), 10)
			// opt.s.WriteString(n)
			// opt.s.WriteString("]) ")

			p := make([]byte, 0, 128)
			d := data[offset : offset+int(t.Nelems)]
			p = strconv.AppendQuote(p, toString(d))

			// opt.s.Write(p)

			// opt.s.WriteByte('\n')
			opt.WriteStrings(space, prefix, " (", opt.toString(t.Type), "[", n, "]) ", toString(p), "\n")
			// fmt.Fprintf(s, "%s%s (%s[%d)) %q\n", space, prefix, toString(t.Type), t.Nelems, data[offset:offset+int(t.Nelems)])
			return true
		}
		cnt := strconv.FormatUint(uint64(t.Nelems), 10)
		opt.WriteStrings(space, prefix, " (", opt.toString(t.Type), "[", cnt, ")) {\n")
		// fmt.Fprintf(s, "%s%s (%s[%d)) {\n", space, prefix, opt.toString(t.Type), t.Nelems)

		for i := 0; i < int(t.Nelems); i++ {
			// childOpt := dumpOption{
			// 	data:    data,
			// 	isStr:   false,
			// 	level:   level + 1,
			// 	offset:  offset + i*sz,
			// 	bitOff:  0,
			// 	bitSize: 0,
			// 	ksyms:   opt.ksyms,
			// 	s:       s,
			// }
			opt.level++
			opt.offset += i * sz
			opt.bitOff = 0
			opt.bitSize = 0
			result := opt.dumpDataByBTF("", t.Type)
			opt.level--
			opt.offset -= i * sz
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")
		// fmt.Fprintf(s, "%s}\n", space)
	case *btf.Int:
		msg := make([]byte, 0, 32)
		switch {
		case t.Encoding == btf.Signed && t.Size == 1:
			d := *(*int8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendInt(msg, int64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Appendf(msg, "%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Signed && t.Size == 2:
			d := *(*int16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendInt(msg, int64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Signed && t.Size == 4:
			d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendInt(msg, int64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Signed && t.Size == 8:
			d := *(*int64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendInt(msg, int64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 1:
			d := *(*uint8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendUint(msg, uint64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Appendf(msg, "%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Unsigned && t.Size == 2:
			d := *(*uint16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendUint(msg, uint64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 4:
			d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendUint(msg, uint64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Unsigned && t.Size == 8:
			d := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
			msg = append(msg, "0x"...)
			msg = strconv.AppendUint(msg, uint64(d), 16)
			// msg = fmt.Sprintf("%#x", d)
		case t.Encoding == btf.Char:
			msg = fmt.Appendf(msg, "%#x", data[offset])
			if data[offset] >= 0x20 && data[offset] <= 0x7e {
				msg = fmt.Appendf(msg, "%#x /* %c */", data[offset], data[offset])
			}
		case t.Encoding == btf.Bool:
			if data[offset] != 0 {
				msg = append(msg, "true"...)
			} else {
				msg = append(msg, "false"...)
			}
			// msg = fmt.Appendf(msg, "%t", data[offset] != 0)
		default:
			msg = fmt.Appendf(msg, "unkown(%v)", t)
		}

		opt.WriteStrings(space, prefix, " (", opt.toString(t), ")", toString(msg), "\n")
		// opt.s.WriteString(space)
		// opt.s.Write([]byte(prefix))
		// opt.s.WriteString(" (")
		// opt.s.WriteString(opt.toString(t))
		// opt.s.WriteString(")")
		// opt.s.Write(msg)
		// opt.s.WriteString("\n")
		// fmt.Fprintf(s, "%s%s (%s)%s\n", space, prefix, toString(t), msg)
	case *btf.Pointer:
		p := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))

		// opt.s.WriteString(space)
		// opt.s.Write([]byte(prefix))
		// opt.s.WriteString(" (")
		// opt.s.WriteString(opt.toString(t))
		// opt.s.WriteString(")")
		// opt.s.WriteString("0x")
		msg := make([]byte, 0, 32)
		msg = strconv.AppendUint(msg, p, 16)
		// opt.s.Write(msg)
		// opt.s.WriteString(" ")
		// opt.s.WriteString(symInfo)
		// opt.s.WriteString("\n")
		opt.WriteStrings(space, prefix, " (", opt.toString(t), ")", "0x", toString(msg), " ")
		if p != 0 {
			if sym := opt.ksyms.SymbolByAddr(p, true); sym.Name != "" {
				opt.WriteStrings("<", sym.Name, ">")
			}
		}
		opt.s.WriteString("\n")
		// fmt.Fprintf(s, "%s%s (%s)%#x %s\n", space, prefix, toString(t), p, symInfo)
	case *btf.Enum:
		if t.Signed {
			d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					opt.WriteStrings(space, prefix, opt.toString(t), value.Name, "\n")
					// fmt.Fprintf(s, "%s%s(%s) %s\n", space, prefix, opt.toString(t), value.Name)
				}
			}
		} else {
			d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					// opt.s.WriteString(space)
					// opt.s.Write([]byte(prefix))
					// opt.s.WriteString("(")
					// opt.s.WriteString(opt.toString(t))
					// opt.s.WriteString(") ")
					// opt.s.WriteString(value.Name)
					// opt.s.WriteString("\n")
					opt.WriteStrings(space, prefix, "(", opt.toString(t), ") ", value.Name, "\n")
					// fmt.Fprintf(s, "%s%s(%s) %s\n", space, prefix, toString(t), value.Name)

				}
			}
		}
	default:
		fmt.Fprintf(s, "%s%s don't know how to print %v\n", space, prefix, t)
	}
	return true
}

var specCache = make(map[string]*btf.Spec)
var baseSpec = sync.OnceValues[*btf.Spec, error](func() (*btf.Spec, error) {
	return btf.LoadKernelSpec()
})

func loadbtfSpec(mod string) (*btf.Spec, error) {

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

func toBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func toString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
