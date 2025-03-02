package funcgraph

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/xixiliguo/efunc/internal/sysinfo"
)

//go:generate bpf2go -cc clang -cflags $BPF_CFLAGS -target amd64,arm64 -type start_event -type func_event -type trace_data -type arg_kind -type arg_addr -type trace_data_flags -type event_data -type trace_constant funcgraph funcgraph.bpf.c -- -I../include

type Event uint8

const (
	CallEvent Event = iota
	StartEvent
	EntryEvent
	RetEvent
)

type EventStat uint8

const (
	CallSucess EventStat = iota
	CallDrop
	StartSucess
	StartDrop
	EntrySucess
	EntryDrop
	RetSucess
	RetDrop
)

type Option struct {
	EntryFuncs        []string
	AllowFuncs        []string
	DenyFuncs         []string
	EntryFuncsOfDwarf map[Symbol]struct{}
	AllowFuncsOfDwarf map[Symbol]struct{}
	EntryFuncExprs    []*FuncExpr
	AllowFuncExprs    []*FuncExpr
	AllowPids         []int
	DenyPids          []int
	AllowComms        []string
	DenyComms         []string
	Verbose           bool
	BpfLog            bool
	DryRun            bool
	MaxEntries        uint32
	Mode              string
	Target            string
	InheritChild      bool
	Duration          uint64
	Depth             uint64
}

type FuncEvent struct {
	Type     uint8
	Task     uint64
	CpuId    uint32
	Depth    uint64
	SeqId    uint64
	Ip       uint64
	Id       uint32
	Time     uint64
	Para     [funcgraphTraceConstantPARA_LEN]uint64
	DataLen  uint16
	DataOff  [MaxTraceCount]int16
	Data     *[MaxTraceDataLen]uint8
	Duration uint64
	Ret      [funcgraphTraceConstantPARA_LEN]uint64
}

type FuncEvents []FuncEvent

func (es *FuncEvents) Add(e FuncEvent) {
	*es = append(*es, e)
}

func (es *FuncEvents) Reset() {
	*es = (*es)[:0]
}

var defaultDenyFuncs = []string{
	"bpf_get_*",
	"bpf_probe_read_*",
	"bpf_map_*",
	"bpf_ringbuf_*",
	"bpf_ktime_get_ns",
	"*migrate*",
	"rcu_read_lock*",
	"rcu_read_unlock*",
	"bpf_lsm_*",
	"check_cfs_rq_runtime",
	"find_busiest_group",
	"find_vma*",
	"btf_sec_info_cmp",
	"copy_to_user_nofault",
}

type FuncGraph struct {
	funcs           []*FuncInfo
	links           []link.Link
	idToFuncs       map[btf.TypeID]*FuncInfo
	verbose         bool
	bpfLog          bool
	dryRun          bool
	ringBufferSize  uint32
	mode            string
	allow_pid_cnt   uint32
	deny_pid_cnt    uint32
	pids            map[uint32]bool
	allow_comm_cnt  uint32
	deny_comm_cnt   uint32
	comms           map[[16]uint8]bool
	ksyms           *KSymCache
	haveKprobeMulti bool
	haveGetFuncIP   bool
	kretOffset      uint64
	bootTime        uint64
	taskToEvents    map[uint64]*FuncEvents
	eventsPool      sync.Pool
	dataPool        sync.Pool
	buf             *bytes.Buffer
	output          *os.File
	stopper         chan os.Signal
	objs            funcgraphObjects
	opt             *dumpOption
	spaceCache      [1024]byte
	targetCmd       *exec.Cmd
	targetCmdError  error
	targetCmdRecv   chan int
	targetCmdSend   chan int
	inheritChild    bool
	duration        uint64
	depth           uint64
}

func NewFuncGraph(opt *Option) (*FuncGraph, error) {

	opt.DenyFuncs = append(opt.DenyFuncs, defaultDenyFuncs...)
	fg := &FuncGraph{
		verbose:        opt.Verbose,
		bpfLog:         opt.BpfLog,
		dryRun:         opt.DryRun,
		output:         os.Stdout,
		ringBufferSize: opt.MaxEntries,
		mode:           opt.Mode,
		idToFuncs:      map[btf.TypeID]*FuncInfo{},
		pids:           map[uint32]bool{},
		comms:          map[[16]uint8]bool{},
		taskToEvents:   map[uint64]*FuncEvents{},
		buf:            bytes.NewBuffer(make([]byte, 0, 4096)),
		targetCmdRecv:  make(chan int),
		targetCmdSend:  make(chan int),
		inheritChild:   opt.InheritChild,
		duration:       opt.Duration,
		depth:          opt.Depth,
	}
	for i := 0; i < len(fg.spaceCache); i++ {
		fg.spaceCache[i] = ' '
	}

	if err := fg.parseOption(opt); err != nil {
		return fg, err
	}
	fg.eventsPool = sync.Pool{
		New: func() interface{} {
			e := make(FuncEvents, 0, 64)
			return &e
		},
	}
	fg.dataPool = sync.Pool{
		New: func() interface{} {
			return &[MaxTraceDataLen]uint8{}
		},
	}

	if opt, err := NewDumpOption(); err != nil {
		return nil, err
	} else {
		fg.opt = opt
	}

	return fg, nil
}

func (fg *FuncGraph) matchSymByExpr(sym Symbol, exprs []*FuncExpr, isEntry bool) (*FuncInfo, bool, error) {
	for _, expr := range exprs {
		if sym.Module == expr.Module && sym.Name == expr.Name {
			id, info := fg.findBTFInfo(sym)
			if info == nil {
				m := ""
				if expr.Module != "" {
					m = expr.Module + ":"
				}
				return nil, false, fmt.Errorf("%s%s has no available btf info", m, expr.Name)
			}
			fn := &FuncInfo{
				IsEntry: isEntry,
				Symbol:  sym,
				id:      id,
				Btfinfo: info,
			}
			fn.InitArgsRet()
			for _, data := range expr.Datas {
				if err := fn.GenTraceData(data); err != nil {
					return nil, false, err
				}
			}
			if len(fn.trace) > MaxTraceCount {
				return nil, false, fmt.Errorf("trace count of %s exceed max %d limit", fn, MaxTraceCount)
			}
			if len(fn.retTrace) > MaxTraceCount {
				return nil, false, fmt.Errorf("ret trace count of %s exceed max %d limit", fn, MaxTraceCount)
			}
			return fn, true, nil
		}
	}
	return nil, false, nil
}

func (fg *FuncGraph) matchSymByDwarf(sym Symbol, funcsOfDwarf map[Symbol]struct{}, isEntry bool) (*FuncInfo, bool) {
	symD := Symbol{
		Name:   sym.Name,
		Addr:   0,
		Module: sym.Module,
	}

	if _, ok := funcsOfDwarf[symD]; ok {
		id, info := fg.findBTFInfo(sym)
		// if info == nil {
		// 	return nil, false
		// }
		fn := &FuncInfo{
			IsEntry: isEntry,
			Symbol:  sym,
			id:      id,
			Btfinfo: info,
		}
		if info != nil {
			fn.InitArgsRet()
		}
		return fn, true
	}

	return nil, false

}

func (fg *FuncGraph) matchSymByGlobs(sym Symbol, globs []string, isEntry bool) (*FuncInfo, bool) {
	for _, name := range globs {
		mod := ""
		s := strings.SplitN(name, ":", 2)
		if len(s) == 2 {
			mod = s[0]
			name = s[1]
		}
		if match, _ := filepath.Match(name, sym.Name); match {

			if mod == sym.Module {
				id, info := fg.findBTFInfo(sym)
				// if info == nil {
				// 	return nil, false
				// }
				fn := &FuncInfo{
					IsEntry: isEntry,
					Symbol:  sym,
					id:      id,
					Btfinfo: info,
				}
				if info != nil {
					fn.InitArgsRet()
				}
				return fn, true
			}
		}
	}
	return nil, false
}

func (fg *FuncGraph) findBTFInfo(sym Symbol) (btf.TypeID, *btf.Func) {

	spec, err := LoadbtfSpec(sym.Module)
	if err != nil {
		return 0, nil
	}

	info := &btf.Func{}
	if err := spec.TypeByName(sym.Name, &info); err != nil {
		if fg.verbose {
			fmt.Printf("cannot find btf info of function %s: %s\n", sym.Name, err)
		}
		return 0, nil
	}
	id, err := spec.TypeID(info)
	if err != nil {
		if fg.verbose {
			fmt.Printf("cannot find btf id of function %s: %s\n", sym.Name, err)
		}
		return 0, nil
	}
	return id, info
}

func (fg *FuncGraph) parseOption(opt *Option) error {

	if opt.Target != "" {
		go fg.startCmd(opt.Target, fg.targetCmdRecv, fg.targetCmdSend)
		<-fg.targetCmdRecv
		if fg.targetCmdError != nil {
			return fg.targetCmdError
		}
		opt.AllowPids = append(opt.AllowPids, fg.targetCmd.Process.Pid)
	}

	ksyms, err := NewKSymCache()
	if err != nil {
		return err
	}
	fg.ksyms = ksyms

	entryCnt := 0
	allowedCnt := 0
	dup := map[string]struct{}{}

	iter := ksyms.Iterate()
	for iter.Next() {
		sym := iter.Symbol
		if _, ok := availKprobeSymbol()[Symbol{
			Name:   sym.Name,
			Module: sym.Module,
		}]; !ok {
			continue
		}

		if _, match := fg.matchSymByGlobs(sym, opt.DenyFuncs, false); match {
			continue
		}

		if fn, match, err := fg.matchSymByExpr(sym, opt.EntryFuncExprs, true); err != nil {
			return err
		} else if match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match := fg.matchSymByDwarf(sym, opt.EntryFuncsOfDwarf, true); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match := fg.matchSymByGlobs(sym, opt.EntryFuncs, true); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match, err := fg.matchSymByExpr(sym, opt.AllowFuncExprs, false); err != nil {
			return err
		} else if match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			allowedCnt++
			continue
		}

		if fn, match := fg.matchSymByDwarf(sym, opt.AllowFuncsOfDwarf, false); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			allowedCnt++
			continue
		}

		if fn, match := fg.matchSymByGlobs(sym, opt.AllowFuncs, false); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			allowedCnt++
			continue
		}

	}

	sort.SliceStable(fg.funcs, func(i, j int) bool {
		// if fg.funcs[i].isEntry == fg.funcs[j].isEntry {
		// 	return fg.funcs[i].Name < fg.funcs[j].Name
		// }
		return fg.funcs[i].IsEntry
	})

	if len(fg.funcs) == 0 || !fg.funcs[0].IsEntry {

		return fmt.Errorf("no entry function")
	}

	fmt.Printf("total %d functions will be traced, entry: %d, child: %d\n",
		len(fg.funcs),
		entryCnt, allowedCnt)

	for _, p := range opt.AllowPids {
		fg.allow_pid_cnt++
		fg.pids[uint32(p)] = true
	}
	for _, p := range opt.DenyPids {
		fg.deny_pid_cnt++
		fg.pids[uint32(p)] = false
	}

	for _, c := range opt.AllowComms {
		fg.allow_comm_cnt++
		key := [16]uint8{}
		copy(key[:], c)
		key[15] = 0
		fg.comms[key] = true
	}
	for _, c := range opt.DenyComms {
		fg.deny_comm_cnt++
		key := [16]uint8{}
		copy(key[:], c)
		key[15] = 0
		fg.comms[key] = false
	}

	return nil
}

func (fg *FuncGraph) Init() error {
	if r, err := os.Open("/proc/stat"); err != nil {
		return err
	} else {
		defer r.Close()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) < 2 {
				continue
			}
			if parts[0] == "btime" {
				if fg.bootTime, err = strconv.ParseUint(parts[1], 10, 64); err != nil {
					return fmt.Errorf("couldn't parse %q (btime): %w", parts[1], err)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("couldn't parse %q: %w", "/proc/stat", err)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fg.haveGetFuncIP = sysinfo.HaveGetFuncIP()
	var err error
	if fg.kretOffset, err = sysinfo.DetectRetOffset(); err != nil {
		return err
	}

	fg.haveKprobeMulti = sysinfo.HaveKprobeMulti()

	fmt.Printf("haveGetFuncIP: %v\nretOffset: %v\nhaveKprobeMulti:%v\n", fg.haveGetFuncIP, fg.kretOffset, fg.haveKprobeMulti)

	return nil
}

func (fg *FuncGraph) showStats() {
	iter := fg.objs.EventStats.Iterate()
	var callSucessCnt, startSucessCnt, entrySucessCnt, retSucessCnt uint64
	var callDropCnt, startDropCnt, entryDropCnt, retDropCnt uint64
	var key, cnt uint64
	for iter.Next(&key, &cnt) {
		switch EventStat(key) {
		case CallSucess:
			callSucessCnt = cnt
		case StartSucess:
			startSucessCnt = cnt
		case EntrySucess:
			entrySucessCnt = cnt
		case RetSucess:
			retSucessCnt = cnt
		case CallDrop:
			callDropCnt = cnt
		case StartDrop:
			startDropCnt = cnt
		case EntryDrop:
			entryDropCnt = cnt
		case RetDrop:
			retDropCnt = cnt
		}
	}
	fmt.Printf("START_EVENT: %d/%d\n", startSucessCnt, startDropCnt)
	fmt.Printf("ENTRY_EVENT: %d/%d\n", entrySucessCnt, entryDropCnt)
	fmt.Printf("RET_EVENT: %d/%d\n", retSucessCnt, retDropCnt)
	fmt.Printf("CALL_EVENT: %d/%d\n", callSucessCnt, callDropCnt)
}

func (fg *FuncGraph) load() error {

	spec, err := loadFuncgraph()
	if err != nil {
		return fmt.Errorf("load funcgraph: %w", err)
	}

	consts := make(map[string]interface{})
	consts["has_bpf_get_func_ip"] = fg.haveGetFuncIP
	consts["kret_offset"] = fg.kretOffset
	consts["verbose"] = fg.bpfLog
	consts["pid_allow_cnt"] = fg.allow_pid_cnt
	consts["pid_deny_cnt"] = fg.deny_pid_cnt
	consts["comm_allow_cnt"] = fg.allow_comm_cnt
	consts["comm_deny_cnt"] = fg.deny_comm_cnt
	consts["duration_ms"] = fg.duration
	consts["max_depth"] = uint8(fg.depth)

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("spec RewriteConstants: %w", err)
	}

	spec.Maps["events"].MaxEntries = fg.ringBufferSize

	if fg.haveKprobeMulti && fg.mode != "kprobe" {
		spec.Programs["funcentry"].AttachType = ebpf.AttachTraceKprobeMulti
		spec.Programs["funcret"].AttachType = ebpf.AttachTraceKprobeMulti
	}

	pidsSpec := spec.Maps["pids_filter"]
	for p, action := range fg.pids {
		pidsSpec.Contents = append(pidsSpec.Contents, ebpf.MapKV{Key: p, Value: action})
	}
	pidsSpec.MaxEntries = uint32(len(pidsSpec.Contents) + 1)
	if fg.inheritChild {
		pidsSpec.MaxEntries += 32
	}

	commSpec := spec.Maps["comms_filter"]
	for comm, action := range fg.comms {
		commSpec.Contents = append(commSpec.Contents, ebpf.MapKV{Key: comm, Value: action})
	}
	commSpec.MaxEntries = uint32(len(commSpec.Contents) + 1)

	basicSpec := spec.Maps["func_basic_info"]
	fnSpec := spec.Maps["func_info"]
	for _, fn := range fg.funcs {
		var name [40]int8
		for i := 0; i < 40 && i < len(fn.Name); i++ {
			name[i] = int8(fn.Name[i])
		}
		basic := funcgraphFuncBasic{
			Id:          uint32(fn.id),
			IsMainEntry: fn.IsEntry,
			Name:        name,
		}
		basicSpec.Contents = append(basicSpec.Contents, ebpf.MapKV{Key: fn.Addr, Value: basic})

		if len(fn.trace) == 0 && len(fn.retTrace) == 0 {
			continue
		}

		f := funcgraphFunc{
			Id:          uint32(fn.id),
			IsMainEntry: fn.IsEntry,
			Name:        name,
		}
		for i, t := range fn.trace {
			if i >= int(funcgraphTraceConstantMAX_TRACES) {
				break
			}
			ft := funcgraphTraceData{
				ArgKind:     t.argKind,
				ArgLoc:      t.IdxOff,
				Size:        uint16(t.size),
				BitOff:      t.bitOff,
				BitSize:     t.bitSize,
				Flags:       t.flags(),
				CmpOperator: t.CmpOperator,
				Target:      t.Target,
			}

			if len(t.TargetStr) != 0 {
				strCnt := 0
				for ; strCnt < 16 && strCnt < len(t.TargetStr); strCnt++ {
					ft.TargetStr[strCnt] = int8(t.TargetStr[strCnt])
				}
				ft.Target = uint64(strCnt)
			}

			copy(ft.Offsets[:], t.offsets)
			ft.FieldCnt = uint8(len(t.offsets))
			f.Trace[i] = ft
			f.TraceCnt++
			if t.CmpOperator != 0 {
				f.HaveFilter = true
			}
		}

		for i, t := range fn.retTrace {
			if i >= int(funcgraphTraceConstantMAX_TRACES) {
				break
			}
			ft := funcgraphTraceData{
				ArgKind:     t.argKind,
				ArgLoc:      t.IdxOff,
				Size:        uint16(t.size),
				BitOff:      t.bitOff,
				BitSize:     t.bitSize,
				Flags:       t.flags(),
				CmpOperator: t.CmpOperator,
				Target:      t.Target,
			}

			if len(t.TargetStr) != 0 {
				strCnt := 0
				for ; strCnt < 16 && strCnt < len(t.TargetStr); strCnt++ {
					ft.TargetStr[strCnt] = int8(t.TargetStr[strCnt])
				}
				ft.Target = uint64(strCnt)
			}

			copy(ft.Offsets[:], t.offsets)
			ft.FieldCnt = uint8(len(t.offsets))
			f.RetTrace[i] = ft
			f.RetTraceCnt++
			if t.CmpOperator != 0 {
				f.HaveRetFilter = true
			}
		}
		fnSpec.Contents = append(fnSpec.Contents, ebpf.MapKV{Key: fn.Addr, Value: f})
	}
	basicSpec.MaxEntries = uint32(len(basicSpec.Contents) + 1)
	fnSpec.MaxEntries = uint32(len(fnSpec.Contents) + 1)

	if err := spec.LoadAndAssign(&fg.objs, nil); err != nil {
		var verifyError *ebpf.VerifierError
		if errors.As(err, &verifyError) {
			fmt.Println(strings.Join(verifyError.Log, "\n"))
			// fmt.Printf("%+v\n", verifyError)
		}
		return fmt.Errorf("spec LoadAndAssign: %w", err)
	}

	return nil
}

func (fg *FuncGraph) startCmd(target string, recv, send chan int) {
	data := strings.Fields(target)

	runtime.LockOSThread()
	cmd := exec.Command(data[0], data[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}

	err := cmd.Start()
	fg.targetCmd = cmd
	fg.targetCmdError = err

	recv <- 1
	<-send
	syscall.PtraceDetach(fg.targetCmd.Process.Pid)
	fg.targetCmdError = cmd.Wait()
	runtime.UnlockOSThread()
	recv <- 2
}

func (fg *FuncGraph) Run() error {

	start := time.Now()
	if err := fg.load(); err != nil {
		return err
	}
	fmt.Printf("load ebpf and update maps take %s\n", time.Since(start))
	if fg.dryRun {
		fmt.Printf("will not run when run dry run mode\n")
		return nil
	}

	if fg.mode != "kprobe" && fg.haveKprobeMulti {
		addrs := []uintptr{}
		for _, f := range fg.funcs {
			addrs = append(addrs, uintptr(f.Addr))
		}
		opts := link.KprobeMultiOptions{
			Addresses: addrs,
		}

		kpMulti, err := link.KprobeMulti(fg.objs.Funcentry, opts)
		if err != nil {
			return fmt.Errorf("opening kprobe-multi: %w", err)
		}
		fmt.Printf("kprobe-multi sucessfully\n")
		defer kpMulti.Close()
		kpMultiRet, err := link.KretprobeMulti(fg.objs.Funcret, opts)
		if err != nil {
			return fmt.Errorf("opening kretprobe-multi: %w", err)
		}
		fmt.Printf("kretprobe-multi sucessfully\n")
		defer kpMultiRet.Close()
	} else {
		for _, f := range fg.funcs {
			kp, err := link.Kprobe(f.Name, fg.objs.Funcentry, nil)
			if err != nil {
				return fmt.Errorf("opening kprobe %s: %w", f.Name, err)
			}
			fmt.Printf("kprobe %s sucessfully\n", f.Name)
			fg.links = append(fg.links, kp)
			kretp, err := link.Kretprobe(f.Name, fg.objs.Funcret, nil)
			if err != nil {
				return fmt.Errorf("opening kretprobe %s: %w", f.Name, err)
			}
			fmt.Printf("kretprobe %s sucessfully\n", f.Name)
			fg.links = append(fg.links, kretp)
		}
	}

	if fg.inheritChild {
		tp_fork, err := link.Tracepoint("sched", "sched_process_fork", fg.objs.HandleFork, nil)
		if err != nil {
			return fmt.Errorf("opening tracepoint sched_process_fork: %w", err)
		}
		defer tp_fork.Close()

		tp_free, err := link.Tracepoint("sched", "sched_process_free", fg.objs.HandleFree, nil)
		if err != nil {
			return fmt.Errorf("opening tracepoint sched_process_free: %w", err)
		}
		defer tp_free.Close()
	}

	err := fg.objs.funcgraphMaps.Ready.Update(uint64(0), true, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("update ready map: %w", err)
	}

	if fg.targetCmd != nil {
		fg.targetCmdSend <- 1
	}

	rd, err := ringbuf.NewReader(fg.objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	fg.stopper = make(chan os.Signal, 1)
	signal.Notify(fg.stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-fg.stopper:
		case <-fg.targetCmdRecv:
			if rd.AvailableBytes() != 0 {
				time.Sleep(100 * time.Millisecond)
			}
		}

		if err := rd.Close(); err != nil {
			fmt.Printf("closing ringbuf reader: %s\n", err)
			os.Exit(1)
		}
	}()

	fmt.Println("Waiting for events..")

	var rec ringbuf.Record
	for {
		err := rd.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("Received signal, exiting..")
				if len(fg.links) != 0 {
					fmt.Printf("closing kprobe events\n")
					for _, l := range fg.links {
						l.Close()
					}
				}
				fg.showStats()
				os.Exit(1)
			}
			fmt.Printf("reading from reader: %s\n", err)
			continue
		}

		switch Event(rec.RawSample[0]) {
		case CallEvent:
			callEvent := (*funcgraphCallEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			// if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &callEvent); err != nil {
			// 	fmt.Printf("parsing ringbuf event: %s\n", err)
			// 	os.Exit(1)
			// }
			fg.handleCallEvent(callEvent)
		case StartEvent:
			startEvent := (*funcgraphStartEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			// if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &startEvent); err != nil {
			// 	fmt.Printf("parsing ringbuf event: %s\n", err)
			// 	os.Exit(1)
			// }

			// when miss last CallEvent, clean all pending events
			// if es, ok := fg.taskToEvents[startEvent.Task]; ok {
			// 	fmt.Printf("no call event received, delete %d events of task %#x anyway\n", len(*es), startEvent.Task)
			delete(fg.taskToEvents, startEvent.Task)
			// }
			empty := fg.eventsPool.Get().(*FuncEvents)
			empty.Reset()
			fg.taskToEvents[startEvent.Task] = empty
		case EntryEvent:
			entryEvent := (*funcgraphFuncEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			task := entryEvent.Task
			e := FuncEvent{
				Type:  entryEvent.Type,
				Task:  entryEvent.Task,
				CpuId: entryEvent.CpuId,
				Depth: entryEvent.Depth,
				SeqId: entryEvent.SeqId,
				Ip:    entryEvent.Ip,
				Id:    entryEvent.Id,
				// Time:  entryEvent.Time,
				Para: entryEvent.Records,
			}
			if entryEvent.HaveData {
				eventData := (*funcgraphEventData)(unsafe.Pointer(&entryEvent.Buf))
				e.DataLen = eventData.DataLen
				e.DataOff = eventData.DataOff
				empty := fg.dataPool.Get().(*[MaxTraceDataLen]uint8)
				e.Data = empty
				copy(e.Data[:], unsafe.Slice(unsafe.SliceData(eventData.Data[:]), MaxTraceDataLen))
			}
			// funcInfo :=
			// if entryEvent.HaveData {
			// 	fmt.Printf("data %+v %+v %+v %+v\n", e.Data[:64], e.DataOff, e.DataLen, fg.idToFuncs[btf.TypeID(e.Id)])
			// }

			//fmt.Printf("receive funcevent %+v\n", funcEvent)
			events := fg.taskToEvents[task]
			events.Add(e)
			fg.taskToEvents[task] = events
		case RetEvent:
			retEvent := (*funcgraphFuncEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			// if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &retEvent); err != nil {
			// 	fmt.Printf("parsing ringbuf event: %s\n", err)
			// 	os.Exit(1)
			// }
			task := retEvent.Task
			// fmt.Printf("receive funcevent %+v\n", funcEvent)

			e := FuncEvent{
				Type:  retEvent.Type,
				Task:  retEvent.Task,
				CpuId: retEvent.CpuId,
				Depth: retEvent.Depth,
				SeqId: retEvent.SeqId,
				Ip:    retEvent.Ip,
				Id:    retEvent.Id,
				// Time:     retEvent.Time,
				Duration: retEvent.Duration,
				Ret:      retEvent.Records,
			}

			if retEvent.HaveData {
				eventData := (*funcgraphEventData)(unsafe.Pointer(&retEvent.Buf))
				e.DataLen = eventData.DataLen
				e.DataOff = eventData.DataOff
				empty := fg.dataPool.Get().(*[MaxTraceDataLen]uint8)
				e.Data = empty
				copy(e.Data[:], unsafe.Slice(unsafe.SliceData(eventData.Data[:]), MaxTraceDataLen))
			}

			events := fg.taskToEvents[task]
			events.Add(e)
			fg.taskToEvents[task] = events
		default:
			fmt.Printf("unknow event type: %c, exiting\n", rec.RawSample[0])
			os.Exit(1)
		}
	}
}

func (fg *FuncGraph) handleCallEvent(event *funcgraphCallEvent) {

	fg.buf.Reset()

	var t [1024]byte
	b := t[:0]

	// start := time.Unix(int64(fg.bootTime), int64(event.StartTime)).Format("15:04:05.000000")
	// end := time.Unix(int64(fg.bootTime), int64(event.EndTime)).Format("15:04:05.000000")

	// fmt.Fprintf(s, "TIME: %s -> %s PID/TID: %d/%d (%s %s) \n", start, end, event.Pid, event.Tid,
	// 	unix.ByteSliceToString(event.GroupComm[:]), unix.ByteSliceToString(event.Comm[:]))

	fg.buf.WriteString("TIME: ")
	b = t[:0]
	b = time.Unix(int64(fg.bootTime), int64(event.StartTime)).AppendFormat(b, "15:04:05.000000")
	fg.buf.Write(b)
	// s.WriteString(start)
	fg.buf.WriteString(" -> ")
	b = t[:0]
	b = time.Unix(int64(fg.bootTime), int64(event.EndTime)).AppendFormat(b, "15:04:05.000000")
	fg.buf.Write(b)
	fg.buf.WriteString(" PID/TID: ")
	b = t[:0]
	b = strconv.AppendUint(b, uint64(event.Pid), 10)
	fg.buf.Write(b)
	// s.WriteString(strconv.FormatUint(uint64(event.Pid), 10))
	fg.buf.WriteString("/")
	b = t[:0]
	b = strconv.AppendUint(b, uint64(event.Tid), 10)
	fg.buf.Write(b)
	// s.WriteString(strconv.FormatUint(uint64(event.Tid), 10))
	fg.buf.WriteString(" (")
	fg.buf.WriteString(ByteSliceToString(event.GroupComm[:]))
	fg.buf.WriteString(" ")
	fg.buf.WriteString(ByteSliceToString(event.Comm[:]))
	fg.buf.WriteString(") \n")

	events := fg.taskToEvents[event.Task]
	fg.handleFuncEvent(events)
	for _, addr := range event.Kstack {
		if addr == 0 {
			break
		}
		sym := fg.ksyms.SymbolByAddr(addr)
		mod := ""
		if sym.Module != "" {
			mod = "[" + sym.Module + "]"
		}
		// stackLine := fmt.Sprintf()
		b = t[:0]
		b = strconv.AppendUint(b, addr-sym.Addr, 16)
		// off := strconv.FormatUint(addr-sym.Addr, 16)
		fg.buf.WriteString(sym.Name)
		fg.buf.WriteString("+0x")
		fg.buf.Write(b)
		fg.buf.WriteString(" ")
		fg.buf.WriteString(mod)
		fg.buf.WriteString("\n")
		// fmt.Fprintf(s, "%s+%#x %s\n", sym.Name, addr-sym.Addr, mod)
		// buf.WriteString(stackLine)
	}
	fg.buf.WriteString("\n")
	fg.output.Write(fg.buf.Bytes())

	for _, e := range *events {
		if e.Data != nil {
			fg.dataPool.Put(e.Data)
		}
		e.Data = nil
	}
	fg.eventsPool.Put(events)
	fg.taskToEvents[event.Task] = nil
	delete(fg.taskToEvents, event.Task)
}

func (fg *FuncGraph) handleFuncEvent(es *FuncEvents) {
	fg.buf.WriteString(" CPU   DURATION | FUNCTION GRAPH\n")
	fg.buf.WriteString(" ---   -------- | --------------\n")
	events := *es
	prevSeqId := uint64(0)

	for i := 0; i < len(events); i++ {
		e := &events[i]
		if gap := e.SeqId - prevSeqId; gap > 1 {
			fg.buf.Write(fg.spaceCache[:e.Depth*2+18])
			fg.buf.WriteString("\u203C ... missing ")
			fg.buf.WriteString(strconv.FormatUint(gap, 10))
			fg.buf.WriteString(" records ...\n")
		}
		d := time.Duration(e.Duration)

		funcInfo := fg.idToFuncs[btf.TypeID(e.Id)]
		if e.Id == 0 {
			sym := fg.ksyms.SymbolByAddr(e.Ip)
			funcInfo.Symbol = sym
		}
		sym := funcInfo.Symbol
		prevSeqId = e.SeqId
		if e.Type == uint8(EntryEvent) {
			if i+1 < len(events) && events[i+1].Type == uint8(RetEvent) &&
				events[i+1].Ip == e.Ip && events[i+1].CpuId == e.CpuId {
				ret := &events[i+1]
				d := time.Duration(ret.Duration)
				id := strconv.FormatInt(int64(e.CpuId), 10)
				if gap := 3 - len(id); gap > 0 {
					fg.buf.Write(fg.spaceCache[:gap])
				}
				fg.buf.WriteString(id)
				fg.buf.WriteString(") ")
				ds := d.String()

				l := len(ds)
				if m := d.Microseconds(); m > 0 && m < 1000 {
					l--
				}
				if gap := 10 - l; gap > 0 {
					fg.buf.Write(fg.spaceCache[:gap])
				}
				fg.buf.WriteString(ds)
				fg.buf.WriteString(" | ")
				fg.buf.Write(fg.spaceCache[:e.Depth*2])
				fg.buf.WriteString("\u2194 ")
				fg.buf.WriteString(sym.Name)
				fg.buf.WriteString(" ")
				if sym.Module != "" {
					fg.buf.WriteString("[")
					fg.buf.WriteString(sym.Module)
					fg.buf.WriteString("] ")
				}
				funcInfo.ShowPara(e, fg.opt, fg.buf)
				// fg.ShowFuncPara(e)
				funcInfo.ShowRet(ret, fg.opt, fg.buf)
				// fg.ShowFuncRet(ret)
				fg.buf.WriteByte('\n')
				//time.Sleep(5 * time.Minute)
				funcInfo.ShowTrace(e, fg.opt, fg.buf)
				funcInfo.ShowRetTrace(ret, fg.opt, fg.buf)

				i++
				prevSeqId = ret.SeqId
			} else {

				id := strconv.FormatInt(int64(e.CpuId), 10)
				if gap := 3 - len(id); gap > 0 {
					fg.buf.Write(fg.spaceCache[:gap])
				}
				fg.buf.WriteString(id)
				fg.buf.WriteString(") ")
				fg.buf.Write(fg.spaceCache[:10])
				fg.buf.WriteString(" | ")
				fg.buf.Write(fg.spaceCache[:e.Depth*2])
				fg.buf.WriteString("\u2192 ")
				fg.buf.WriteString(sym.Name)
				fg.buf.WriteString(" ")
				if sym.Module != "" {
					fg.buf.WriteString("[")
					fg.buf.WriteString(sym.Module)
					fg.buf.WriteString("] ")
				}
				funcInfo.ShowPara(e, fg.opt, fg.buf)
				fg.buf.WriteByte('\n')
				funcInfo.ShowTrace(e, fg.opt, fg.buf)
			}
		} else {
			id := strconv.FormatInt(int64(e.CpuId), 10)
			if gap := 3 - len(id); gap > 0 {
				fg.buf.Write(fg.spaceCache[:gap])
			}
			fg.buf.WriteString(id)
			fg.buf.WriteString(") ")
			ds := d.String()
			l := len(ds)
			if m := d.Microseconds(); m > 0 && m < 1000 {
				l--
			}
			if gap := 10 - l; gap > 0 {
				fg.buf.Write(fg.spaceCache[:gap])
			}
			fg.buf.WriteString(ds)
			fg.buf.WriteString(" | ")
			fg.buf.Write(fg.spaceCache[:e.Depth*2])
			fg.buf.WriteString("\u2190 ")
			fg.buf.WriteString(sym.Name)
			fg.buf.WriteString(" ")
			if sym.Module != "" {
				fg.buf.WriteString("[")
				fg.buf.WriteString(sym.Module)
				fg.buf.WriteString("] ")
			}
			funcInfo.ShowRet(e, fg.opt, fg.buf)
			fg.buf.WriteByte('\n')
			funcInfo.ShowRetTrace(e, fg.opt, fg.buf)

		}
	}
	fg.buf.WriteByte('\n')
}
