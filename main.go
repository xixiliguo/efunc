package main

import (
	"fmt"
	"maps"
	"os"
	"regexp"

	"github.com/cilium/ebpf/btf"
	"github.com/urfave/cli/v2"
	"github.com/xixiliguo/efunc/internal/funcgraph"
	"github.com/xixiliguo/efunc/internal/sysinfo"
)

func main() {
	cli.AppHelpTemplate = fmt.Sprintf(`%s
EXAMPLES:
	efunc info
	efunc debug "ip_rcv"
	efunc debug "ip_rcv(*skb, skb->len, skb->dev.name)"
	efunc trace -e "ip_rcv(skb->len)" -a ":net/ipv4/*" -a "virtio_net:*"	
	efunc trace -e "tcp_v4_rcv(skb, skb->head, skb->transport_header, (struct tcphdr *)(1,2,1,0)->syn == 1)"

ENVIRONMENT:
	BTF_SHOW_ZERO		[default: 0] show field info even value is zero
	`, cli.AppHelpTemplate)
	app := &cli.App{
		Usage:   "A eBPF-based trace tool like ftrace funcgraph",
		Version: "0.1.6",
		Commands: []*cli.Command{
			{
				Name:  "debug",
				Usage: "parse func expr and generate trace data",
				Action: func(cCtx *cli.Context) error {
					fn := cCtx.Args().First()
					expr, err := funcgraph.ParseFuncWithPara(fn)
					if err != nil {
						return fmt.Errorf("parsing %q\n%w", fn, err)
					}
					fmt.Printf("parsing %s\n", fn)
					fmt.Printf("expr: %+v\n\n", expr)

					spec, err := funcgraph.LoadbtfSpec(expr.Module)
					if err != nil {
						return err
					}

					typ, err := spec.AnyTypeByName(expr.Name)
					if err != nil {
						return err
					}
					if btfData, ok := typ.(*btf.Func); ok {
						s := funcgraph.ShowBtfFunc(btfData)
						fmt.Printf("%s\n\n", s)
						fn := &funcgraph.FuncInfo{
							IsEntry: true,
							Btfinfo: btfData,
						}
						fn.InitArgsRet()
						for _, data := range expr.Datas {
							fn.GenTraceData(data)
						}
					} else {
						return fmt.Errorf("expect function but got %+v", typ)
					}

					return nil
				},
			},
			{
				Name:  "info",
				Usage: "show system info and detected ebpf feature",
				Action: func(cCtx *cli.Context) error {
					i, err := sysinfo.ShowSysInfo()
					if err != nil {
						return err
					}
					fmt.Println(i)
					return nil
				},
			},
			{
				Name:  "trace",
				Usage: "trace func graph and latency",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:     "entry",
						Aliases:  []string{"e"},
						Required: true,
						Usage:    "entry function that trigger funcgraph trace",
						Action: func(ctx *cli.Context, s []string) error {
							for _, ss := range s {
								if ss == "" {
									return fmt.Errorf("entry function can not empty string")
								}
							}
							return nil
						},
					},
					&cli.StringSliceFlag{
						Name:    "allow",
						Aliases: []string{"a"},
						Value:   nil,
						Usage:   "allowed function that will be capatured",
						Action: func(ctx *cli.Context, s []string) error {
							for _, ss := range s {
								if ss == "" {
									return fmt.Errorf("allowed function can not empty string")
								}
							}
							return nil
						},
					},
					&cli.StringSliceFlag{
						Name:    "deny",
						Aliases: []string{"d"},
						Value:   nil,
						Usage:   "deny function that will be skipped",
						Action: func(ctx *cli.Context, s []string) error {
							for _, ss := range s {
								if ss == "" {
									return fmt.Errorf("deny function can not empty string")
								}
							}
							return nil
						},
					},
					&cli.IntSliceFlag{
						Name:    "pid",
						Aliases: []string{"p"},
						Value:   nil,
						Usage:   "only trace given `PID`",
					},
					&cli.IntSliceFlag{
						Name:    "no-pid",
						Aliases: []string{"P"},
						Value:   nil,
						Usage:   "skip tracing given `PID`",
					},
					&cli.StringSliceFlag{
						Name:  "comm",
						Value: nil,
						Usage: "only trace processes with given name (aka `COMM`)",
						Action: func(ctx *cli.Context, s []string) error {
							for _, ss := range s {
								if ss == "" {
									return fmt.Errorf("comm can not empty string")
								}
							}
							return nil
						},
					},
					&cli.StringSliceFlag{
						Name:  "no-comm",
						Value: nil,
						Usage: "skip tracing processes with given name (aka `COMM`)",
						Action: func(ctx *cli.Context, s []string) error {
							for _, ss := range s {
								if ss == "" {
									return fmt.Errorf("no-comm can not empty string")
								}
							}
							return nil
						},
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Value:   false,
						Usage:   "verbose output",
					},
					&cli.BoolFlag{
						Name:  "bpf-log",
						Value: false,
						Usage: "print verbose message in kernel ebpf side",
					},
					&cli.BoolFlag{
						Name:  "dry-run",
						Value: false,
						Usage: "only test purpose, do not load bpf prog",
					},
					&cli.UintFlag{
						Name:  "max-trace-size",
						Value: 1024,
						Usage: "maximum `SIZE` of every trace data in bytes",
						Action: func(ctx *cli.Context, u uint) error {
							if u < 8 {
								return fmt.Errorf("max-trace-size must not be allowed below 8")
							}
							if u&(u-1) != 0 {
								return fmt.Errorf("max-trace-size must be pow of 2: %d", u)
							}
							return nil
						},
					},
					&cli.UintFlag{
						Name:  "max-ringbuf-size",
						Value: 1024 * 1024 * 16,
						Usage: "maximum `SIZE` of ringbuffer in bytes",
						Action: func(ctx *cli.Context, u uint) error {
							if u == 0 {
								return fmt.Errorf("max-ringbuf-size must not be allowed to 0")
							}
							if u&(u-1) != 0 {
								return fmt.Errorf("max-ringbuf-size must be pow of 2: %d", u)
							}
							return nil
						},
					},
					&cli.StringFlag{
						Name:  "mode",
						Value: "auto",
						Usage: "trace mode, only support auto, multi-kprobe or kprobe",
						Action: func(ctx *cli.Context, s string) error {
							if s != "auto" && s != "multi-kprobe" && s != "kprobe" {
								return fmt.Errorf("support auto, multi-kprobe or kprobe")
							}
							return nil
						},
					},
					&cli.StringFlag{
						Name:    "command",
						Aliases: []string{"cmd"},
						Usage:   "trace only given command",
						Action: func(ctx *cli.Context, s string) error {
							if s != "" &&
								(ctx.IntSlice("pid") != nil || ctx.IntSlice("no-pid") != nil ||
									ctx.StringSlice("comm") != nil || ctx.StringSlice("no-comm") != nil) {
								return fmt.Errorf("command can not combine with pid, no-pid, comm, no-comm")
							}
							return nil
						},
					},
					&cli.BoolFlag{
						Name:  "inherit",
						Usage: "trace children processes",
						Action: func(ctx *cli.Context, b bool) error {
							if b &&
								ctx.IntSlice("pid") == nil &&
								ctx.String("command") == "" {
								return fmt.Errorf("must specfic pid or command with inherit option")
							}
							return nil
						},
					},
					&cli.Uint64Flag{
						Name:  "duration",
						Usage: "show trace with duration >= xx ms",
					},
					&cli.Uint64Flag{
						Name:  "depth",
						Usage: "max call trace depth, value range (0,32]",
						Value: 32,
						Action: func(ctx *cli.Context, i uint64) error {
							if i == 0 || i > 32 {
								return fmt.Errorf("depth rage must (0,32]")
							}
							return nil
						},
					},
				},
				Action: func(ctx *cli.Context) error {
					exprFmt, _ := regexp.Compile(`.*\(.*\)`)
					entryFuncs := []string{}
					entryFuncExprs := []*funcgraph.FuncExpr{}
					entryFuncsOfDwarf := map[funcgraph.Symbol]struct{}{}
					for _, e := range ctx.StringSlice("entry") {
						if exprFmt.MatchString(e) {
							if fe, err := funcgraph.ParseFuncWithPara(e); err == nil {
								entryFuncExprs = append(entryFuncExprs, fe)
							} else {
								return fmt.Errorf("parsing %s\n%w", e, err)
							}
						} else if e[0] == ':' {
							maps.Copy(entryFuncsOfDwarf, funcgraph.FuncsFromFile(e[1:]))
						} else {
							entryFuncs = append(entryFuncs, e)
						}
					}

					allowFuncs := []string{}
					allowFuncExprs := []*funcgraph.FuncExpr{}
					allowFuncsOfDwarf := map[funcgraph.Symbol]struct{}{}
					for _, a := range ctx.StringSlice("allow") {
						if exprFmt.MatchString(a) {
							if fe, err := funcgraph.ParseFuncWithPara(a); err == nil {
								allowFuncExprs = append(allowFuncExprs, fe)
							} else {
								return fmt.Errorf("parsing %s\n%w", a, err)
							}
						} else if a[0] == ':' {
							maps.Copy(allowFuncsOfDwarf, funcgraph.FuncsFromFile(a[1:]))
						} else {
							allowFuncs = append(allowFuncs, a)
						}
					}

					opt := funcgraph.Option{
						EntryFuncs:        entryFuncs,
						AllowFuncs:        allowFuncs,
						DenyFuncs:         ctx.StringSlice("deny"),
						EntryFuncExprs:    entryFuncExprs,
						AllowFuncExprs:    allowFuncExprs,
						EntryFuncsOfDwarf: entryFuncsOfDwarf,
						AllowFuncsOfDwarf: allowFuncsOfDwarf,
						AllowPids:         ctx.IntSlice("pid"),
						DenyPids:          ctx.IntSlice("no-pid"),
						AllowComms:        ctx.StringSlice("comm"),
						DenyComms:         ctx.StringSlice("no-comm"),
						Verbose:           ctx.Bool("verbose"),
						BpfLog:            ctx.Bool("bpf-log"),
						DryRun:            ctx.Bool("dry-run"),
						MaxTraceSize:      uint32(ctx.Uint("max-trace-size")),
						MaxRingSize:       uint32(ctx.Uint("max-ringbuf-size")),
						Mode:              ctx.String("mode"),
						Target:            ctx.String("command"),
						InheritChild:      ctx.Bool("inherit"),
						Duration:          ctx.Uint64("duration"),
						Depth:             ctx.Uint64("depth"),
					}

					fg, err := funcgraph.NewFuncGraph(&opt)
					if err != nil {
						return err
					}
					if err := fg.Init(); err != nil {
						return err
					}
					if err := fg.Run(); err != nil {
						return err
					}
					return nil
				},
			},
		},
	}
	app.DisableSliceFlagSeparator = true

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}
