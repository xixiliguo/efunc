package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

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
	Dereference bool    `parser:"@DereferenceOperator?"`
	First       string  `parser:"@Ident"`
	Fields      []Field `parser:"@@*"`
	SohwString  bool    `parser:"@ShowString?"`
	CompareInfo Compare `parser:"@@?"`
}

type Field struct {
	Name string `parser:"ArrowOperator@(Ident (Period Ident)*)"`
}

type Compare struct {
	Operator  string `parser:"Whitespace@Operator"`
	Threshold Value  `parser:"Whitespace@@"`
}

type Value struct {
	String *string `parser:"@Ident"`
	Int    *int    `parser:"| @Number"`
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
	Name    string
	onEntry bool
	isStr   bool
	Typ     btf.Type
	Para    int
	Offsets []uint32
	Size    int
	BitOff  uint32
	BitSize uint32
}

func genTraceData(dataExpr DataExpr, fn *btf.Func) *TraceData {
	fmt.Printf("generate TraceData of %+v with %+v\n", dataExpr, fn)
	t := &TraceData{}
	var btfData btf.Type
	proto := fn.Type.(*btf.FuncProto)

	if dataExpr.First != "ret" {
		for idx, para := range proto.Params {
			if dataExpr.First == para.Name {
				t.Name = para.Name
				t.onEntry = true
				t.Para = idx
				t.Size = 8
				t.Typ = para.Type
				btfData = para.Type
				break
			}
		}
	} else {
		t.Name = "ret"
		t.onEntry = false
		t.Size = 8
		t.Typ = proto.Return
		btfData = proto.Return
	}

	if btfData != nil {
		if dataExpr.Dereference {
			dataExpr.Fields = append(dataExpr.Fields, Field{
				Name: "",
			})
		}
		genTraceDataByField(dataExpr.Fields, 0, btfData, t)
	} else {
		fmt.Printf("%s is not parameter of %s\n", dataExpr.First, fn)
		os.Exit(1)
	}
	if dataExpr.SohwString {
		t.isStr = true
		t.Size = 1024
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
	if f.Name != "" {
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
	}
	t.Typ = currStructType
	t.Offsets = append(t.Offsets, offset)
	if sz, err := btf.Sizeof(currStructType); err == nil {
		t.Size = sz
	} else {
		fmt.Printf("%+v cannot get size: %s\n", currStructType, err)
		os.Exit(1)
	}
	if f.Name != "" {
		t.Name += "->" + f.Name
	} else {
		t.Name = "*" + t.Name
	}

	genTraceDataByField(fs, idx+1, currStructType, t)

}

var funcParserFunc = sync.OnceValue[*participle.Parser[FuncExpr]](func() *participle.Parser[FuncExpr] {
	clexer := lexer.MustSimple([]lexer.SimpleRule{
		{Name: "DereferenceOperator", Pattern: `\*`},
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
		{Name: "Number", Pattern: `\d+`},
	})

	parser, _ := participle.Build[FuncExpr](participle.Lexer(clexer))
	return parser
})

func ParseFuncWithPara(s string) (*FuncExpr, error) {
	p := funcParserFunc()
	return p.ParseString("", s)
}

func showBtfFunc(fn *btf.Func) (s string) {
	if proto, ok := fn.Type.(*btf.FuncProto); ok {
		s = typToString(proto.Return)
		s += fmt.Sprintf(" %s(", fn.Name)
		paras := []string{}
		for _, para := range proto.Params {
			paras = append(paras, typToString(para.Type)+para.Name)
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
