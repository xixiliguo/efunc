package funcgraph

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

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
	ShowString  bool     `parser:"@ShowString?"`
	CompareInfo Compare  `parser:"@@?"`
}

func (d DataExpr) String() string {
	re := ""
	if d.Dereference {
		re += "*"
	}
	if d.Typ.Name != "" {
		m := ""
		if d.Typ.Moudle != "" {
			m = d.Typ.Moudle + ":"
		}
		re += fmt.Sprintf("(struct %s%s *)", m, d.Typ.Name)
	}
	if d.First.Name != "" {
		re += d.First.Name
	} else {
		re += fmt.Sprintf("(%d,%d,%d,%d)",
			d.First.Addr.Base,
			d.First.Addr.Index,
			d.First.Addr.Scale,
			d.First.Addr.Imm)
	}
	for _, f := range d.Fields {
		re += "->" + f.Name
	}
	if d.ShowString {
		re += ":str"
	}
	if d.CompareInfo.Operator != "" {
		re += " " + d.CompareInfo.Operator + " " + d.CompareInfo.Threshold.s
	}
	return re
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
	Name  string `parser:"ArrowOperator@(Ident (Period Ident)*)"`
	Index Value  `parser:"(LeftBracket @Number RightBracket)?"`
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
	return "", errors.New("characters must be included in double quotes")
}

func (v Value) ShowSignNumber() (int64, error) {
	return strconv.ParseInt(v.s, 0, 64)
}

func (v Value) ShowUnsignNumber() (uint64, error) {
	return strconv.ParseUint(v.s, 0, 64)
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
		{Name: "LeftBracket", Pattern: `\[`},
		{Name: "RightBracket", Pattern: `\]`},
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
