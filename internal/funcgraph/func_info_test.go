package funcgraph

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFuncExpr(t *testing.T) {

	cases := []struct {
		input  string
		output *FuncExpr
		isErr  bool
	}{
		{input: "tcp_v4_rcv(skb, skb->head, skb->transport_header, (struct tcphdr *)(1,2,1,0)->syn == 1)",
			output: &FuncExpr{
				Module: "",
				Name:   "tcp_v4_rcv",
				Datas: []DataExpr{
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "skb"},
						Fields:      nil,
						Func:        BuiltInFuncNone,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "skb"},
						Fields:      []Field{{[]Token{Token{Name: "head"}}}},
						Func:        BuiltInFuncNone,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "skb"},
						Fields:      []Field{{[]Token{Token{Name: "transport_header"}}}},
						Func:        BuiltInFuncNone,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{Name: "tcphdr"},
						First:       Primary{Addr: Addr{Base: 1, Index: 2, Scale: 1, Imm: 0}},
						Fields:      []Field{{[]Token{Token{Name: "syn"}}}},
						Func:        BuiltInFuncNone,
						CompareInfo: Compare{
							Operator:  "==",
							Threshold: Value{s: "1"},
						},
					},
				},
			},
		},
		{input: `do_filp_open(pathname->name:str == "/etc/hosts")`,
			output: &FuncExpr{
				Module: "",
				Name:   "do_filp_open",
				Datas: []DataExpr{
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "pathname"},
						Fields:      []Field{{[]Token{Token{Name: "name"}}}},
						Func:        BuiltInFuncString,
						CompareInfo: Compare{
							Operator:  "==",
							Threshold: Value{s: `"/etc/hosts"`},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		if re, err := ParseFuncWithPara(c.input); err != nil {
			if !c.isErr {
				t.Errorf("parse %q should no error, but got %s", c.input, err)
			}
		} else {
			opts := []cmp.Option{
				cmp.AllowUnexported(Value{}),
			}
			if !cmp.Equal(re, c.output, opts...) {
				t.Fatalf("data should be the same\n%s\n", cmp.Diff(re, c.output, opts...))
			}
		}
	}

}
