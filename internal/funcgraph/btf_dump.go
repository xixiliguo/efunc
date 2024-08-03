package funcgraph

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

type dumpOption struct {
	data           []byte
	isStr          bool
	level          int
	showZero       bool
	ksyms          *KSymCache
	buf            *bytes.Buffer
	spaceCache     [1024]byte
	typStringCache map[btf.Type]string
	typSizeCache   map[btf.Type]int
}

func NewDumpOption() (*dumpOption, error) {
	k, err := NewKSymCache()
	if err != nil {
		return nil, err
	}
	isShow := false
	if v := os.Getenv("BTF_SHOW_ZERO"); v == "1" {
		isShow = true
	}
	d := dumpOption{
		data:           nil,
		isStr:          false,
		level:          0,
		showZero:       isShow,
		ksyms:          k,
		buf:            bytes.NewBuffer(make([]byte, 0, 4096)),
		typStringCache: make(map[btf.Type]string),
		typSizeCache:   make(map[btf.Type]int),
	}
	for i := 0; i < len(d.spaceCache); i++ {
		d.spaceCache[i] = ' '
	}

	return &d, nil
}

func (opt *dumpOption) Reset(data []byte, isStr bool, level int) {
	opt.data = data
	opt.isStr = isStr
	opt.level = level
	opt.buf.Reset()
}

func (opt *dumpOption) String() string {
	return toString(opt.buf.Bytes())
}

func (opt *dumpOption) typString(typ btf.Type) string {
	if s, ok := opt.typStringCache[typ]; ok {
		return s
	}
	re := typToString(typ)
	opt.typStringCache[typ] = re
	return re
}

func (opt *dumpOption) typSize(typ btf.Type) (int, error) {
	if sz, ok := opt.typSizeCache[typ]; ok {
		return sz, nil
	}
	sz, err := btf.Sizeof(typ)
	if err != nil {
		return sz, err
	}
	opt.typSizeCache[typ] = sz
	return sz, nil
}

func (opt *dumpOption) WriteStrings(ss ...string) {
	for i := 0; i < len(ss); i++ {
		opt.buf.WriteString(ss[i])
	}
}

func (opt *dumpOption) dumpDataByBTF(name string, typ btf.Type, offset, bitOff, bitSize int) bool {

	level := opt.level
	data := opt.data

	space := toString(opt.spaceCache[:2*level])
	if sz, err := opt.typSize(typ); err != nil {
		opt.WriteStrings(space, "don't know ", name, " size: ", err.Error(), "\n")
		return false
	} else {
		if offset != 0 && offset+sz > len(data) {
			cnt := strconv.FormatInt(int64(offset), 10)
			opt.WriteStrings(space, "/* only show first ", cnt, " bytes */\n")
			return false
		}
		i := 0
		for ; i < sz; i++ {
			if data[offset+i] != 0 {
				break
			}
		}
		if !opt.showZero && i == sz && offset != 0 {
			return true
		}
	}

	connector := ""
	if name != "" {
		connector = " = "
	}

	if opt.isStr {
		re := ByteSliceToString(data[offset:])
		opt.WriteStrings(space, name, connector, re, "\n")
		return true
	}

	typ = btf.UnderlyingType(typ)
	switch t := typ.(type) {
	case *btf.Union:
		opt.WriteStrings(space, name, connector, "(", opt.typString(t), ") {\n")
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			opt.level++
			bitOff = int(memBitOff)
			bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type, offset+int(memOff), bitOff, bitSize)
			opt.level--
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")
	case *btf.Struct:
		opt.WriteStrings(space, name, connector, "(", opt.typString(t), ") {\n")
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			opt.level++
			bitOff = int(memBitOff)
			bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type, offset+int(memOff), bitOff, bitSize)
			opt.level--
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")

	case *btf.Array:
		// special case for char[]
		sz, _ := btf.Sizeof(t.Type)
		if end := offset + int(t.Nelems); sz == 1 && end <= len(data) {
			n := strconv.FormatUint(uint64(t.Nelems), 10)
			p := make([]byte, 0, 128)
			d := data[offset : offset+int(t.Nelems)]
			p = strconv.AppendQuote(p, toString(d))
			opt.WriteStrings(space, name, connector, "(", opt.typString(t.Type), "[", n, "]) ", toString(p), "\n")
			return true
		}
		cnt := strconv.FormatUint(uint64(t.Nelems), 10)
		opt.WriteStrings(space, name, connector, "(", opt.typString(t.Type), "[", cnt, ")) {\n")
		for i := 0; i < int(t.Nelems); i++ {
			opt.level++
			result := opt.dumpDataByBTF(strconv.Itoa(i), t.Type, offset+i*sz, bitOff, bitSize)
			opt.level--
			if !result {
				return false
			}
		}
		opt.WriteStrings(space, "}\n")
	case *btf.Int:
		msg := make([]byte, 0, 16)
		if bitSize != 0 {
			var num uint64
			for i := int(t.Size - 1); i >= 0; i-- {
				num = num*256 + uint64(data[offset+i])
			}
			left := 64 - bitOff - bitSize
			right := 64 - bitSize
			num = (num << uint64(left)) >> uint64(right)
			if !opt.showZero && num == 0 && offset != 0 {
				return true
			}
			if t.Encoding == btf.Signed {
				msg = strconv.AppendInt(msg, int64(num), 10)
			} else {
				msg = strconv.AppendUint(msg, uint64(num), 10)
			}
		} else {
			switch {
			case t.Encoding == btf.Signed && t.Size == 1:
				d := *(*int8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendInt(msg, int64(d), 10)
				if data[offset] >= 0x20 && data[offset] <= 0x7e {
					msg = append(msg, " /* "...)
					msg = append(msg, data[offset])
					msg = append(msg, " */"...)
				}
			case t.Encoding == btf.Signed && t.Size == 2:
				d := *(*int16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendInt(msg, int64(d), 10)
			case t.Encoding == btf.Signed && t.Size == 4:
				d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendInt(msg, int64(d), 10)
			case t.Encoding == btf.Signed && t.Size == 8:
				d := *(*int64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendInt(msg, int64(d), 10)
			case t.Encoding == btf.Unsigned && t.Size == 1:
				d := *(*uint8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendUint(msg, uint64(d), 10)
				if data[offset] >= 0x20 && data[offset] <= 0x7e {
					msg = append(msg, " /* "...)
					msg = append(msg, data[offset])
					msg = append(msg, " */"...)
				}
			case t.Encoding == btf.Unsigned && t.Size == 2:
				d := *(*uint16)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendUint(msg, uint64(d), 10)
			case t.Encoding == btf.Unsigned && t.Size == 4:
				d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendUint(msg, uint64(d), 10)
			case t.Encoding == btf.Unsigned && t.Size == 8:
				d := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendUint(msg, uint64(d), 10)
			case t.Encoding == btf.Char:
				d := *(*uint8)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
				msg = strconv.AppendUint(msg, uint64(d), 10)
				if data[offset] >= 0x20 && data[offset] <= 0x7e {
					msg = append(msg, " /* "...)
					msg = append(msg, data[offset])
					msg = append(msg, " */"...)
				}
			case t.Encoding == btf.Bool:
				if data[offset] != 0 {
					msg = append(msg, "true"...)
				} else {
					msg = append(msg, "false"...)
				}
			default:
				msg = fmt.Appendf(msg, "unkown(%v)", t)
			}
		}
		opt.WriteStrings(space, name, connector, "(", opt.typString(t), ")", toString(msg), "\n")
	case *btf.Pointer:
		p := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
		msg := make([]byte, 0, 32)
		msg = strconv.AppendUint(msg, p, 16)
		opt.WriteStrings(space, name, connector, "(", opt.typString(t), ")", "0x", toString(msg), " ")
		if p != 0 {
			if sym := opt.ksyms.SymbolByAddr(p); sym.Addr == p {
				opt.WriteStrings("<", sym.Name, ">")
			}
		}
		opt.buf.WriteString("\n")
	case *btf.Enum:
		if t.Signed {
			d := *(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					opt.WriteStrings(space, name, connector, "(", opt.typString(t), ")", value.Name, "\n")
				}
			}
		} else {
			d := *(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)])))
			for _, value := range t.Values {
				if value.Value == uint64(d) {
					opt.WriteStrings(space, name, connector, "(", opt.typString(t), ")", value.Name, "\n")
				}
			}
		}
	case *btf.Void:
		opt.WriteStrings(space, name, connector, "void", "\n")
	default:
		typ := fmt.Sprintf("%v", t)
		opt.WriteStrings(space, name, connector, "don't know how to print ", typ, "\n")
	}
	return true
}

var specCache = make(map[string]*btf.Spec)
var baseSpec = sync.OnceValues[*btf.Spec, error](func() (*btf.Spec, error) {
	return btf.LoadKernelSpec()
})

func LoadbtfSpec(mod string) (*btf.Spec, error) {

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

// func toBytes(s string) []byte {
// 	if len(s) == 0 {
// 		return nil
// 	}
// 	return unsafe.Slice(unsafe.StringData(s), len(s))
// }

func toString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func ByteSliceToString(s []byte) string {
	if i := bytes.IndexByte(s, 0); i != -1 {
		s = s[:i]
	}
	return toString(s)
}
