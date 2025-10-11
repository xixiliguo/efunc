package funcgraph

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
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
	ksym           *KernelSymbolizer
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

	if ksym, err := NewKsymbolizer(); err != nil {
		return nil, err
	} else {
		d.ksym = ksym
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

func findOffsetFromStruct(s *btf.Struct, name string) (int, btf.Type, bool) {

	for _, m := range s.Members {
		if m.Name == name {
			return int(m.Offset.Bytes()), m.Type, true
		}
		if m.Name == "" {
			base := int(m.Offset.Bytes())
			switch typ := m.Type.(type) {
			case *btf.Struct:
				off, childTyp, found := findOffsetFromStruct(typ, name)
				if found {
					return base + off, childTyp, found
				}
			case *btf.Union:
				off, childTyp, found := findOffsetFromUnion(typ, name)
				if found {
					return base + off, childTyp, found
				}
			}
		}
	}
	return 0, nil, false
}

func findOffsetFromUnion(s *btf.Union, name string) (int, btf.Type, bool) {

	for _, m := range s.Members {
		if m.Name == name {
			return int(m.Offset.Bytes()), m.Type, true
		}
		if m.Name == "" {
			base := int(m.Offset.Bytes())
			switch typ := m.Type.(type) {
			case *btf.Struct:
				off, childTyp, found := findOffsetFromStruct(typ, name)
				if found {
					return base + off, childTyp, found
				}
			case *btf.Union:
				off, childTyp, found := findOffsetFromUnion(typ, name)
				if found {
					return base + off, childTyp, found
				}
			}
		}
	}
	return 0, nil, false
}

func findOffset(s *btf.Struct, names string) (int, bool) {

	fields := strings.Split(names, ".")
	var start btf.Type
	start = s
	totalOff := 0
	for _, f := range fields {
		switch typ := start.(type) {
		case *btf.Struct:
			off, childTyp, found := findOffsetFromStruct(typ, f)
			if !found {
				return 0, false
			}
			totalOff += off
			start = childTyp
		case *btf.Union:
			off, childTyp, found := findOffsetFromUnion(typ, f)
			if !found {
				return 0, false
			}
			totalOff += off
			start = childTyp
		default:
			return 0, false
		}
	}
	return totalOff, true
}

func (opt *dumpOption) appendComment(typ *btf.Struct, offset int) {

	if offset+int(typ.Size) > len(opt.data) {
		return
	}

	if opt.compact {
		return
	}

	space := toString(opt.spaceCache[:2*(opt.level+1)])

	if typ.Name == "sock" {
		opt.buf.WriteString(space)
		opt.buf.WriteString("/* ")
		if off, found := findOffset(typ, "__sk_common.skc_family"); found {
			family := binary.NativeEndian.Uint16(opt.data[offset+off:])
			switch family {
			case unix.AF_UNIX:
				opt.buf.WriteString("UNIX ")
			case unix.AF_NETLINK:
				opt.buf.WriteString("NETLINK ")
			case unix.AF_PACKET:
				opt.buf.WriteString("PACKET ")
			case unix.AF_INET:
				opt.buf.WriteString("IPV4 ")
				if off, found := findOffset(typ, "sk_protocol"); found {
					t := binary.NativeEndian.Uint16(opt.data[offset+off:])
					switch t {
					case unix.IPPROTO_UDP:
						opt.buf.WriteString("UDP ")
						offSaddr, found1 := findOffset(typ, "__sk_common.skc_rcv_saddr")
						offSport, found2 := findOffset(typ, "__sk_common.skc_num")
						offDaddr, found3 := findOffset(typ, "__sk_common.skc_daddr")
						offDport, found4 := findOffset(typ, "__sk_common.skc_dport")
						if found1 && found2 && found3 && found4 {
							s := opt.data[offset+offSaddr:]
							d := opt.data[offset+offDaddr:]
							saddr := net.IPv4(s[0], s[1], s[2], s[3])
							sport := binary.NativeEndian.Uint16(opt.data[offset+offSport:])
							daddr := net.IPv4(d[0], d[1], d[2], d[3])
							dport := binary.BigEndian.Uint16(opt.data[offset+offDport:])
							fmt.Fprintf(opt.buf, " %s:%d --> %s:%d ",
								saddr, sport,
								daddr, dport)
						}
					case unix.IPPROTO_TCP:
						opt.buf.WriteString("TCP ")
						offSaddr, found1 := findOffset(typ, "__sk_common.skc_rcv_saddr")
						offSport, found2 := findOffset(typ, "__sk_common.skc_num")
						offDaddr, found3 := findOffset(typ, "__sk_common.skc_daddr")
						offDport, found4 := findOffset(typ, "__sk_common.skc_dport")
						if found1 && found2 && found3 && found4 {
							s := opt.data[offset+offSaddr:]
							d := opt.data[offset+offDaddr:]
							saddr := net.IPv4(s[0], s[1], s[2], s[3])
							sport := binary.NativeEndian.Uint16(opt.data[offset+offSport:])
							daddr := net.IPv4(d[0], d[1], d[2], d[3])
							dport := binary.BigEndian.Uint16(opt.data[offset+offDport:])
							fmt.Fprintf(opt.buf, "LOCAL: %s:%d --> REMOTE: %s:%d ",
								saddr, sport,
								daddr, dport)
						}
					default:
						opt.buf.WriteString("UNKNOWN PROTOCOL ")
					}
				}
			case unix.AF_INET6:
				opt.buf.WriteString("IPV6 ")
			default:
				opt.buf.WriteString("UNKNOWN FAMILY ")
			}
		}
		opt.buf.WriteString(" */\n")
	}

	if typ.Name == "iphdr" {
		len := binary.BigEndian.Uint16(opt.data[offset+2:])
		id := binary.BigEndian.Uint16(opt.data[offset+4:])

		prot := opt.data[offset+9]
		p := "UNKNOWN PROTOCOL"
		switch prot {
		case unix.IPPROTO_ICMP:
			p = "ICMP"
		case unix.IPPROTO_TCP:
			p = "TCP"
		case unix.IPPROTO_UDP:
			p = "UDP"
		}
		s := opt.data[offset+12:]
		src := net.IPv4(s[0], s[1], s[2], s[3])
		d := opt.data[offset+16:]
		dst := net.IPv4(d[0], d[1], d[2], d[3])

		opt.buf.WriteString(space)
		fmt.Fprintf(opt.buf, "/* IPV4 LEN: %d ID: %d  %s  ADDR: %s --> %s */\n",
			len, id,
			p,
			src, dst)
	}

	if typ.Name == "tcphdr" {
		src := binary.BigEndian.Uint16(opt.data[offset:])
		dst := binary.BigEndian.Uint16(opt.data[offset+2:])

		seq := binary.BigEndian.Uint32(opt.data[offset+4:])
		ack := binary.BigEndian.Uint32(opt.data[offset+8:])

		flags := make([]byte, 0, 8)
		b := opt.data[offset+13]
		if b&1 != 0 {
			flags = append(flags, 'F')
		}
		if b&2 != 0 {
			flags = append(flags, 'S')
		}
		if b&4 != 0 {
			flags = append(flags, 'R')
		}
		if b&8 != 0 {
			flags = append(flags, 'P')
		}
		if b&16 != 0 {
			flags = append(flags, '.')
		}
		opt.buf.WriteString(space)
		fmt.Fprintf(opt.buf, "/* PORT: %d --> %d FLAGS: [%s] SEQ %d ACK %d */\n",
			src, dst,
			flags,
			seq, ack)
	}

	if typ.Name == "udphdr" {
		src := binary.BigEndian.Uint16(opt.data[offset:])
		dst := binary.BigEndian.Uint16(opt.data[offset+2:])
		len := binary.BigEndian.Uint16(opt.data[offset+4:])

		opt.buf.WriteString(space)
		fmt.Fprintf(opt.buf, "/* PORT: %d --> %d LEN: %d */\n",
			src, dst, len)
	}

	if typ.Name == "icmphdr" {
		t := opt.data[offset]
		code := opt.data[offset+1]
		id := binary.BigEndian.Uint16(opt.data[offset+4:])
		sequence := binary.BigEndian.Uint16(opt.data[offset+6:])

		opt.buf.WriteString(space)
		fmt.Fprintf(opt.buf, "/* TYPE: %d CODE: %d ID: %d SEQ: %d */\n",
			t, code, id, sequence)
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

		opt.appendComment(t, offset)

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
			ksym := KernelSymbol{}
			if err := opt.ksym.SymbolByAddr(p, &ksym); err == nil && ksym.Addr == p {
				opt.WriteStrings(" <", ksym.Name, ">")
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
