package funcgraph

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/cilium/ebpf/btf"
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
	Base  uint8 `parser:"@Number"`
	Index uint8 `parser:"Separator @Number"`
	Scale int16 `parser:"Separator @Number"`
	Imm   int16 `parser:"Separator @Number"`
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

type FuncInfo struct {
	isEntry bool
	Symbol
	id       btf.TypeID
	btfinfo  *btf.Func
	trace    []*TraceData
	retTrace []*TraceData
}

type TraceData struct {
	Name        string
	onEntry     bool
	isStr       bool
	Typ         btf.Type
	BaseAddr    bool
	Para        int
	Base        uint8
	Index       uint8
	Scale       int16
	Imm         int16
	Offsets     []uint32
	Size        int
	BitOff      uint32
	BitSize     uint32
	isSign      bool
	CmpOperator uint8
	Target      uint64
}

func GenTraceData(dataExpr DataExpr, fn *btf.Func) *TraceData {
	fmt.Printf("generate TraceData of %+v with %+v\n", dataExpr, fn)
	t := &TraceData{}
	var btfData btf.Type
	proto := fn.Type.(*btf.FuncProto)

	if dataExpr.First.Name != "" {
		if dataExpr.First.Name != "ret" {
			for idx, para := range proto.Params {
				if dataExpr.First.Name == para.Name {
					t.Name = para.Name
					t.onEntry = true
					t.Para = idx
					t.Size, _ = btf.Sizeof(para.Type)
					t.Typ = para.Type
					btfData = para.Type
					break
				}
			}
		} else {
			t.Name = "ret"
			t.onEntry = false
			t.Size, _ = btf.Sizeof(proto.Return)
			t.Typ = proto.Return
			btfData = proto.Return
		}

	} else {
		t.Name = fmt.Sprintf("(struct %s *)(%d,%d,%d,%d)", dataExpr.Typ.Name,
			dataExpr.First.Addr.Base,
			dataExpr.First.Addr.Index,
			dataExpr.First.Addr.Scale,
			dataExpr.First.Addr.Imm)
		if len(dataExpr.Fields) != 0 {
			t.Name = "(" + t.Name + ")"
		}
		t.BaseAddr = true
		t.Base = dataExpr.First.Addr.Base
		t.Index = dataExpr.First.Addr.Index
		t.Scale = dataExpr.First.Addr.Scale
		t.Imm = dataExpr.First.Addr.Imm
		t.onEntry = true

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
		t.Typ = pointer
		t.Size, _ = btf.Sizeof(pointer)
		btfData = pointer
		dataExpr.Typ.Name = ""
	}

	fmt.Println(dataExpr.First, btfData)

	if btfData != nil {

		genTraceDataByField(dataExpr.Fields, 0, btfData, t)

		if dataExpr.Typ.Name != "" {
			if _, ok := t.Typ.(*btf.Pointer); ok {
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
				t.Typ = pointer
				t.Name = fmt.Sprintf("(struct %s *)%s", dataExpr.Typ, t.Name)

			} else {
				fmt.Printf("type cast only support pointer type: source type is %+v\n", t.Typ)
				os.Exit(1)
			}
		}

		if dataExpr.Dereference {
			btfData := btf.UnderlyingType(t.Typ)
			btfPointerData, ok := btfData.(*btf.Pointer)
			if !ok {
				fmt.Printf("%+v is not pointer type\n", btfData)
				os.Exit(1)
			}
			t.Typ = btfPointerData.Target
			t.Offsets = append(t.Offsets, 0)
			if sz, err := btf.Sizeof(t.Typ); err == nil {
				t.Size = sz
			} else {
				fmt.Printf("%+v cannot get size: %s\n", t.Typ, err)
				os.Exit(1)
			}
			t.Name = "*" + t.Name
		}

	} else {
		fmt.Printf("%+v is not parameter of %s\n", dataExpr.First, fn)
		os.Exit(1)
	}
	if dataExpr.SohwString {
		t.isStr = true
		t.Size = 1024
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
			switch typ := btf.UnderlyingType(t.Typ).(type) {
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
	return t
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
	offset := uint32(0)

	fields := strings.Split(f.Name, ".")
	for _, name := range fields {
		currStructType = btf.UnderlyingType(currStructType)
		off, bitOff, bitSize, typ, found := caculateOffset(name, currStructType)
		if !found {
			fmt.Printf("%+v is not field of %+v\n", name, currStructType)
			os.Exit(1)
		}
		currStructType = typ
		offset += off
		t.BitOff = bitOff
		t.BitSize = bitSize
	}

	t.Typ = currStructType
	t.Offsets = append(t.Offsets, offset)
	if sz, err := btf.Sizeof(currStructType); err == nil {
		t.Size = sz
	} else {
		fmt.Printf("%+v cannot get size: %s\n", currStructType, err)
		os.Exit(1)
	}

	t.Name += "->" + f.Name

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
