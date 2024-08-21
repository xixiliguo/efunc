package funcgraph

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestFuncExpr(t *testing.T) {

	one := "1"

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
						SohwString:  false,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "skb"},
						Fields:      []Field{{Name: "head"}},
						SohwString:  false,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{},
						First:       Primary{Name: "skb"},
						Fields:      []Field{{Name: "transport_header"}},
						SohwString:  false,
						CompareInfo: Compare{},
					},
					{
						Dereference: false,
						Typ:         CastType{Name: "tcphdr"},
						First:       Primary{Addr: Addr{Base: 1, Index: 2, Scale: 1, Imm: 0}},
						Fields:      []Field{{Name: "syn"}},
						SohwString:  false,
						CompareInfo: Compare{
							Operator:  "==",
							Threshold: Value{Int: &one},
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
				cmpopts.IgnoreUnexported(),
			}
			if !cmp.Equal(re, c.output, opts...) {
				t.Fatalf("data should be the same\n%s\n", cmp.Diff(re, c.output, opts...))
			}
		}
	}

}
