package funcgraph

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

type dumpOption struct {
	data           []byte
	isStr          bool
	level          int
	showZero       bool
	buf            *bytes.Buffer
	spaceCache     [1024]byte
	typStringCache map[btf.Type]string
	typSizeCache   map[btf.Type]int
	compact        bool
}

func NewDumpOption() (*dumpOption, error) {
	isShow := false
	if v := os.Getenv("BTF_SHOW_ZERO"); v == "1" {
		isShow = true
	}
	d := dumpOption{
		data:           nil,
		isStr:          false,
		level:          0,
		showZero:       isShow,
		buf:            bytes.NewBuffer(make([]byte, 0, 4096)),
		typStringCache: make(map[btf.Type]string),
		typSizeCache:   make(map[btf.Type]int),
	}
	for i := 0; i < len(d.spaceCache); i++ {
		d.spaceCache[i] = ' '
	}

	return &d, nil
}

func (opt *dumpOption) Reset(data []byte, isStr bool, level int, compact bool) {
	opt.data = data
	opt.isStr = isStr
	opt.level = level
	opt.compact = compact
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

func (opt *dumpOption) appendComment(name string, typ btf.Type, offset, bitOff, bitSize int) {

	if def, ok := typ.(*btf.Typedef); ok && strings.HasPrefix(def.Name, "__be") {
		msg := make([]byte, 0, 16)
		i := uint64(0)
		if def.Name == "__be16" {
			if name == "source" || name == "dest" {
				i = uint64(binary.BigEndian.Uint16(opt.data[offset:]))
				msg = strconv.AppendUint(msg, i, 10)
				opt.WriteStrings("    /* ", "port", " ", toString(msg), " */")
				return
			}
		} else if def.Name == "__be32" {
			if name == "saddr" || name == "daddr" {
				if ip, ok := netip.AddrFromSlice(opt.data[offset : offset+4]); ok {
					if msg, err := ip.AppendText(msg); err == nil {
						opt.WriteStrings("    /* ", "ip", " ", toString(msg), " */")
					} else {
						opt.WriteStrings("    /* ", "error", " ", err.Error(), " */")
					}
				}
				return
			}
		}
	}
}

func (opt *dumpOption) dumpDataByBTF(name string, typ btf.Type, offset, bitOff, bitSize int) int {

	level := opt.level
	data := opt.data

	space := toString(opt.spaceCache[:2*level])
	if opt.compact {
		space = ""
	}

	sz, err := opt.typSize(typ)
	if err != nil {
		opt.WriteStrings(space, "don't know ", name, " size: ", err.Error())
		return -1
	} else {
		if offset != 0 && offset+sz > len(data) {
			cnt := strconv.FormatInt(int64(offset), 10)
			opt.WriteStrings(space, "/* only show first ", cnt, " bytes */")
			return -1
		}
		i := 0
		for ; i < sz && offset+i < len(data); i++ {
			if data[offset+i] != 0 {
				break
			}
		}
		if !opt.showZero && i == sz && offset != 0 {
			return 0
		}
	}
	span := "\n"

	if opt.compact {
		span = ""

	}
	connector := ""
	if name != "" {
		connector = " = "
		if opt.compact {
			connector = "="
		}
	}

	if opt.isStr {
		re := ByteSliceToString(data[offset:])
		opt.WriteStrings(space, name, connector, re)
		return sz
	}

	switch t := btf.UnderlyingType(typ).(type) {
	case *btf.Union:
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		opt.WriteStrings("{", span)
		sep := "\n"
		if opt.compact {
			sep = ","
		}
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			opt.level++
			bitOff = int(memBitOff)
			bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type, offset+int(memOff), bitOff, bitSize)
			opt.level--
			if result < 0 {
				return result
			}
			if result == 0 {
				continue
			}
			opt.WriteStrings(sep)
		}
		// opt.WriteStrings(span)
		opt.WriteStrings(space, "}")
	case *btf.Struct:
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		opt.WriteStrings("{", span)
		sep := "\n"
		if opt.compact {
			sep = ","
		}
		for _, mem := range t.Members {
			memOff, memBitOff := mem.Offset/8, mem.Offset%8
			opt.level++
			bitOff = int(memBitOff)
			bitSize = int(mem.BitfieldSize)
			result := opt.dumpDataByBTF(mem.Name, mem.Type, offset+int(memOff), bitOff, bitSize)
			opt.level--
			if result < 0 {
				return result
			}
			if result == 0 {
				continue
			}
			opt.WriteStrings(sep)
		}
		// opt.WriteStrings(span)
		opt.WriteStrings(space, "}")

	case *btf.Array:
		// special case for char[]
		sz, _ := btf.Sizeof(t.Type)
		if end := offset + int(t.Nelems); sz == 1 && end <= len(data) {
			n := strconv.FormatUint(uint64(t.Nelems), 10)
			p := make([]byte, 0, 128)
			d := data[offset : offset+int(t.Nelems)]
			p = strconv.AppendQuote(p, toString(d))
			opt.WriteStrings(space, name, connector)
			if !opt.compact {
				opt.WriteStrings("(", opt.typString(t.Type), "[", n, "]) ")
			}
			opt.WriteStrings(toString(p))
			return sz
		}
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		opt.WriteStrings(" {", span)
		sep := "\n"
		if opt.compact {
			sep = ","
		}
		for i := 0; i < int(t.Nelems); i++ {
			opt.level++
			result := opt.dumpDataByBTF(strconv.Itoa(i), t.Type, offset+i*sz, bitOff, bitSize)
			opt.level--
			if result < 0 {
				return result
			}
			if result == 0 {
				continue
			}
			opt.WriteStrings(sep)
		}
		// opt.WriteStrings(span)
		opt.WriteStrings(space, "}")
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
				return 0
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
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		opt.WriteStrings(toString(msg))
	case *btf.Pointer:
		p := *(*uint64)(unsafe.Pointer(unsafe.SliceData(data[offset:])))
		msg := make([]byte, 0, 32)
		msg = strconv.AppendUint(msg, p, 16)
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		opt.WriteStrings("0x", toString(msg))
		if p != 0 && !opt.compact {
			if sym, err := SymbolByAddr(p); err == nil && sym.Addr == p {
				opt.WriteStrings(" <", sym.Name, ">")
			}
		}
	case *btf.Enum:
		opt.WriteStrings(space, name, connector)
		if !opt.compact {
			opt.WriteStrings("(", opt.typString(t), ")")
		}
		more := false
		unknown := true
		var d uint64
		if t.Signed {
			d = uint64(*(*int32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)]))))

		} else {
			d = uint64(*(*uint32)(unsafe.Pointer(unsafe.SliceData(data[offset : offset+int(t.Size)]))))
		}
		for _, value := range t.Values {
			if value.Value == d {
				if more {
					opt.WriteStrings("|")
				}
				opt.WriteStrings(value.Name)
				more = true
				unknown = false
			}
		}
		if unknown {
			v := strconv.FormatUint(uint64(d), 10)
			opt.WriteStrings("unkown(", v, ")")
		}
	case *btf.Void:
		opt.WriteStrings(space, name, connector, "void")
	default:
		typ := fmt.Sprintf("%v", t)
		opt.WriteStrings(space, name, connector, "don't know how to print ", typ)
	}
	opt.appendComment(name, typ, offset, bitOff, bitSize)
	return sz
}

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
