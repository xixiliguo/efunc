package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

//go:generate bpf2go -cc clang -cflags $BPF_CFLAGS fake nanosleep.bpf.c -- -D__TARGET_ARCH_x86 -I./include

//go:generate bpf2go -cc clang -cflags $BPF_CFLAGS -type start_event -type func_entry_event -type func_ret_event -type trace_data funcgraph funcgraph.bpf.c -- -D__TARGET_ARCH_x86 -I./include

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
	entryFuncs        []string
	allowFuncs        []string
	denyFuncs         []string
	entryFuncsOfDwarf map[Symbol]struct{}
	allowFuncsOfDwarf map[Symbol]struct{}
	entryFuncExprs    []*FuncExpr
	allowFuncExprs    []*FuncExpr
	allowPids         []int
	denyPids          []int
	allowComms        []string
	denyComms         []string
	verbose           bool
	bpfLog            bool
	dryRun            bool
	maxEntries        uint32
	mode              string
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
	Para     [5]uint64
	Buf      *[5120]uint8
	Duration uint64
	Ret      uint64
}

type FuncEvents []FuncEvent

func (es *FuncEvents) Add(e FuncEvent) {
	*es = append(*es, e)
}

func (es *FuncEvents) Reset() {
	*es = (*es)[:0]
}

type FuncGraph struct {
	funcs           []FuncInfo
	links           []link.Link
	idToFuncs       map[btf.TypeID]FuncInfo
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
	ksyms           KSymCache
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
}

func NewFuncGraph(opt Option) (*FuncGraph, error) {
	fg := &FuncGraph{
		verbose:        opt.verbose,
		bpfLog:         opt.bpfLog,
		dryRun:         opt.dryRun,
		output:         os.Stdout,
		ringBufferSize: opt.maxEntries,
		mode:           opt.mode,
		idToFuncs:      map[btf.TypeID]FuncInfo{},
		pids:           map[uint32]bool{},
		comms:          map[[16]uint8]bool{},
		taskToEvents:   map[uint64]*FuncEvents{},
		buf:            bytes.NewBuffer(make([]byte, 0, 4096)),
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
			return &[5120]uint8{}
		},
	}

	if opt, err := NewDumpOption(); err != nil {
		return nil, err
	} else {
		fg.opt = opt
	}

	return fg, nil
}

func (fg *FuncGraph) matchSymByExpr(sym Symbol, exprs []*FuncExpr, isEntry bool) (FuncInfo, bool) {
	for _, expr := range exprs {
		if sym.Module == expr.Module && sym.Name == expr.Name {
			id, info := fg.findBTFInfo(sym)
			fn := FuncInfo{
				isEntry: isEntry,
				Symbol:  sym,
				id:      id,
				btfinfo: info,
			}
			for _, data := range expr.Datas {
				t := genTraceData(data, info)
				if int(t.Base) > len(fn.trace) {
					continue
				}
				if int(t.Index) > len(fn.trace) {
					continue
				}
				if t.onEntry {
					fn.trace = append(fn.trace, t)
				} else {
					fn.retTrace = append(fn.retTrace, t)
				}
			}
			return fn, true
		}
	}
	return FuncInfo{}, false
}

func (fg *FuncGraph) matchSymByDwarf(sym Symbol, funcsOfDwarf map[Symbol]struct{}, isEntry bool) (FuncInfo, bool) {
	symD := Symbol{
		Name:   sym.Name,
		Addr:   0,
		Module: sym.Module,
	}

	if _, ok := funcsOfDwarf[symD]; ok {
		id, info := fg.findBTFInfo(sym)
		fn := FuncInfo{
			isEntry: isEntry,
			Symbol:  sym,
			id:      id,
			btfinfo: info,
		}
		return fn, true
	}

	return FuncInfo{}, false

}

func (fg *FuncGraph) matchSymByGlobs(sym Symbol, globs []string, isEntry bool) (FuncInfo, bool) {
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
				fn := FuncInfo{
					isEntry: isEntry,
					Symbol:  sym,
					id:      id,
					btfinfo: info,
				}
				return fn, true
			}
		}
	}
	return FuncInfo{}, false
}

func (fg *FuncGraph) findBTFInfo(sym Symbol) (btf.TypeID, *btf.Func) {

	spec, err := loadbtfSpec(sym.Module)
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

func (fg *FuncGraph) parseOption(opt Option) error {

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
		if !isAvailKprobeSymbol(sym) {
			continue
		}

		if _, match := fg.matchSymByGlobs(sym, opt.denyFuncs, false); match {
			continue
		}

		if fn, match := fg.matchSymByExpr(sym, opt.entryFuncExprs, true); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match := fg.matchSymByDwarf(sym, opt.entryFuncsOfDwarf, true); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match := fg.matchSymByGlobs(sym, opt.entryFuncs, true); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			entryCnt++
			continue
		}

		if fn, match := fg.matchSymByExpr(sym, opt.allowFuncExprs, false); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			allowedCnt++
			continue
		}

		if fn, match := fg.matchSymByDwarf(sym, opt.allowFuncsOfDwarf, false); match {
			if _, ok := dup[sym.Module+sym.Name]; ok {
				continue
			}
			dup[sym.Module+sym.Name] = struct{}{}
			fg.funcs = append(fg.funcs, fn)
			fg.idToFuncs[fn.id] = fn
			allowedCnt++
			continue
		}

		if fn, match := fg.matchSymByGlobs(sym, opt.allowFuncs, false); match {
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
		return fg.funcs[i].isEntry
	})

	if len(fg.funcs) == 0 || !fg.funcs[0].isEntry {

		return fmt.Errorf("no entry function")
	}

	fmt.Printf("total %d functions will be traced, entry: %d, child: %d\n",
		len(fg.funcs),
		entryCnt, allowedCnt)

	for _, p := range opt.allowPids {
		fg.allow_pid_cnt++
		fg.pids[uint32(p)] = true
	}
	for _, p := range opt.denyPids {
		fg.deny_pid_cnt++
		fg.pids[uint32(p)] = false
	}

	for _, c := range opt.allowComms {
		fg.allow_comm_cnt++
		key := [16]uint8{}
		copy(key[:], c)
		key[15] = 0
		fg.comms[key] = true
	}
	for _, c := range opt.denyComms {
		fg.deny_comm_cnt++
		key := [16]uint8{}
		copy(key[:], c)
		key[15] = 0
		fg.comms[key] = false
	}

	return nil
}

func (fg *FuncGraph) init() error {

	if fs, err := procfs.NewFS("/proc"); err != nil {
		return err
	} else {
		if stats, err := fs.Stat(); err != nil {
			return err
		} else {
			fg.bootTime = stats.BootTime
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnGetFuncIp)
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			fg.haveGetFuncIP = false
		} else {
			return err
		}
	} else {
		fg.haveGetFuncIP = true
	}

	if fg.kretOffset, err = fg.detectRetOffset(); err != nil {
		return err
	}
	fg.detectKprobeMulti()

	fmt.Printf("haveGetFuncIP: %v\nretOffset: %v\nhaveKprobeMulti:%v\n", fg.haveGetFuncIP, fg.kretOffset, fg.haveKprobeMulti)

	return nil
}

func (fg *FuncGraph) detectKprobeMulti() {

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})

	if err != nil {
		return
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{
		Symbols: []string{"vprintk"},
	}

	kp, err := link.KprobeMulti(prog, opts)
	if err != nil {
		return
	}
	defer kp.Close()
	fg.haveKprobeMulti = true
}

func (fg *FuncGraph) detectRetOffset() (uint64, error) {
	fakeObjs := fakeObjects{}
	if err := loadFakeObjects(&fakeObjs, nil); err != nil {
		return 0, fmt.Errorf("loading fakeobjects: %w", err)
	}
	defer fakeObjs.Close()

	fakeKp, err := link.Kprobe("sys_nanosleep", fakeObjs.Funcentry, nil)
	if err != nil {
		return 0, fmt.Errorf("opening kprobe sys_nanosleep: %w", err)
	}
	defer fakeKp.Close()

	fakeKpRet, err := link.Kretprobe("sys_nanosleep", fakeObjs.Funcret, nil)
	if err != nil {
		return 0, fmt.Errorf("opening kretprobe sys_nanosleep: %w", err)
	}
	defer fakeKpRet.Close()

	t := unix.Timespec{
		Sec:  0,
		Nsec: 1000,
	}
	unix.Nanosleep(&t, nil)

	for {
		e := unix.Nanosleep(&t, nil)
		if e == nil {
			break
		}
		if e == syscall.EINTR {
			continue
		}
	}
	key := uint64(0)
	value := uint64(0)
	if err := fakeObjs.RetOffset.Lookup(&key, &value); err != nil {
		return 0, fmt.Errorf("RetOffset map lookup: %w", err)
	}
	return value, nil
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

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("spec RewriteConstants: %w", err)
	}

	spec.Maps["events"].MaxEntries = fg.ringBufferSize

	if fg.haveKprobeMulti {
		spec.Programs["funcentry"].AttachType = ebpf.AttachTraceKprobeMulti
		spec.Programs["funcret"].AttachType = ebpf.AttachTraceKprobeMulti
	}
	if err := spec.LoadAndAssign(&fg.objs, nil); err != nil {
		var verifyError *ebpf.VerifierError
		if errors.As(err, &verifyError) {
			fmt.Println(strings.Join(verifyError.Log, "\n"))
		}
		return fmt.Errorf("spec LoadAndAssign: %w", err)
	}

	fmt.Printf("%+v %s\n", fg.objs, err)

	for _, fn := range fg.funcs {

		b, _ := unix.ByteSliceFromString(fn.Name)
		var name [40]uint8
		copy(name[:], b)
		name[len(name)-1] = 0
		f := funcgraphFunc{
			Id:          uint32(fn.id),
			IsMainEntry: fn.isEntry,
			Name:        name,
		}
		// f.TraceCnt = uint8(len(fn.trace))
		for i, t := range fn.trace {
			ft := funcgraphTraceData{
				BaseAddr:    t.BaseAddr,
				Para:        uint8(t.Para),
				Base:        t.Base,
				Index:       t.Index,
				Scale:       t.Scale,
				Imm:         t.Imm,
				IsStr:       t.isStr,
				FieldCnt:    uint8(len(t.Offsets)),
				Offsets:     [20]uint32{},
				Size:        uint16(t.Size),
				IsSign:      t.isSign,
				CmpOperator: t.CmpOperator,
				Target:      t.Target,
				S_target:    t.S_target,
				BitOff:      t.BitOff,
				BitSize:     t.BitSize,
			}
			copy(ft.Offsets[:], t.Offsets)
			f.Trace[i] = ft
			f.TraceCnt++
		}
		for i, t := range fn.retTrace {
			ft := funcgraphTraceData{
				Para:     uint8(t.Para),
				IsStr:    t.isStr,
				FieldCnt: uint8(len(t.Offsets)),
				Offsets:  [20]uint32{},
				Size:     uint16(t.Size),
			}
			copy(ft.Offsets[:], t.Offsets)
			f.RetTrace[i] = ft
			f.RetTraceCnt++
		}
		err = fg.objs.funcgraphMaps.FuncInfo.Update(fn.Addr, f, ebpf.UpdateAny)
		if err != nil {
			return err
		}
	}

	for p, action := range fg.pids {
		err = fg.objs.funcgraphMaps.PidsFilter.Update(p, action, ebpf.UpdateAny)
		if err != nil {
			return err
		}
	}

	for comm, action := range fg.comms {
		err = fg.objs.funcgraphMaps.CommsFilter.Update(comm, action, ebpf.UpdateAny)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fg *FuncGraph) run() error {
	if fg.dryRun {
		fmt.Printf("will not run when run dry run mode\n")
		return nil
	}

	if err := fg.load(); err != nil {
		return err
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

	err := fg.objs.funcgraphMaps.Ready.Update(uint64(0), true, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("update ready map: %w", err)
	}

	rd, err := ringbuf.NewReader(fg.objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	fg.stopper = make(chan os.Signal, 1)
	signal.Notify(fg.stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-fg.stopper
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
			if es, ok := fg.taskToEvents[startEvent.Task]; ok {
				fmt.Printf("no call event received, delete %d events of task %#x anyway\n", len(*es), startEvent.Task)
				delete(fg.taskToEvents, startEvent.Task)
			}
			empty := fg.eventsPool.Get().(*FuncEvents)
			empty.Reset()
			fg.taskToEvents[startEvent.Task] = empty
		case EntryEvent:
			entryEvent := (*funcgraphFuncEntryEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			task := entryEvent.Task
			if _, ok := fg.taskToEvents[task]; !ok {
				fmt.Printf("no trace_start event before receive entry event of task %#x\n", task)
			}
			e := FuncEvent{
				Type:  entryEvent.Type,
				Task:  entryEvent.Task,
				CpuId: entryEvent.CpuId,
				Depth: entryEvent.Depth,
				SeqId: entryEvent.SeqId,
				Ip:    entryEvent.Ip,
				Id:    entryEvent.Id,
				Time:  entryEvent.Time,
				Para:  entryEvent.Para,
			}
			if entryEvent.HaveData {
				empty := fg.dataPool.Get().(*[5120]uint8)
				e.Buf = empty
				copy(e.Buf[:], unsafe.Slice(unsafe.SliceData(entryEvent.Buf[:]), 5120))
			}

			// fmt.Printf("receive funcevent %+v\n", funcEvent)
			events := fg.taskToEvents[task]
			events.Add(e)
			fg.taskToEvents[task] = events
		case RetEvent:
			retEvent := (*funcgraphFuncRetEvent)(unsafe.Pointer(unsafe.SliceData(rec.RawSample)))
			// if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &retEvent); err != nil {
			// 	fmt.Printf("parsing ringbuf event: %s\n", err)
			// 	os.Exit(1)
			// }
			task := retEvent.Task
			if _, ok := fg.taskToEvents[task]; !ok {
				fmt.Printf("no trace_start event before receive ret event of task %#x\n", task)
			}
			// fmt.Printf("receive funcevent %+v\n", funcEvent)

			e := FuncEvent{
				Type:     retEvent.Type,
				Task:     retEvent.Task,
				CpuId:    retEvent.CpuId,
				Depth:    retEvent.Depth,
				SeqId:    retEvent.SeqId,
				Ip:       retEvent.Ip,
				Id:       retEvent.Id,
				Time:     retEvent.Time,
				Duration: retEvent.Duration,
				Ret:      retEvent.Ret,
			}

			if retEvent.HaveData {
				empty := fg.dataPool.Get().(*[5120]uint8)
				e.Buf = empty
				copy(e.Buf[:], unsafe.Slice(unsafe.SliceData(retEvent.Buf[:]), 5120))
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
		sym := fg.ksyms.SymbolByAddr(addr, false)
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
		if e.Buf != nil {
			fg.dataPool.Put(e.Buf)
		}
		e.Buf = nil
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
			sym := fg.ksyms.SymbolByAddr(e.Ip, true)
			funcInfo.Symbol = sym
		}
		sym := funcInfo.Symbol
		prevSeqId = e.SeqId
		if e.Type == uint8(EntryEvent) {
			if i+1 < len(events) && events[i+1].Type == uint8(RetEvent) && events[i+1].Ip == e.Ip {
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
				fg.ShowFuncPara(e)
				fg.buf.WriteByte(' ')
				fg.ShowFuncRet(ret)
				fg.buf.WriteByte('\n')
				for idx, t := range funcInfo.trace {
					off := idx * 1024
					sz := t.Size
					if sz > 1024 {
						sz = 1024
					}
					fg.opt.Reset(e.Buf[off:off+sz], t.isStr, int(10+e.Depth))
					fg.opt.dumpDataByBTF(t.Name, t.Typ, 0, int(t.BitOff), int(t.BitSize))
					fg.buf.WriteString(fg.opt.String())
					fg.buf.WriteString("\n")
				}

				for idx, t := range funcInfo.retTrace {
					off := idx * 1024
					sz := t.Size
					if sz > 1024 {
						sz = 1024
					}
					fg.opt.Reset(ret.Buf[off:off+sz], t.isStr, int(10+e.Depth))
					fg.opt.dumpDataByBTF(t.Name, t.Typ, 0, int(t.BitOff), int(t.BitSize))
					fg.buf.WriteString(fg.opt.String())
					fg.buf.WriteString("\n")
				}

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
				fg.ShowFuncPara(e)
				fg.buf.WriteByte('\n')
				for idx, t := range funcInfo.trace {
					off := idx * 1024
					sz := t.Size
					if sz > 1024 {
						sz = 1024
					}
					fg.opt.Reset(e.Buf[off:off+sz], t.isStr, int(10+e.Depth))
					fg.opt.dumpDataByBTF(t.Name, t.Typ, 0, int(t.BitOff), int(t.BitSize))
					fg.buf.WriteString(fg.opt.String())
				}
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
			fg.ShowFuncRet(e)
			fg.buf.WriteByte('\n')
			for idx, t := range funcInfo.retTrace {
				off := idx * 1024
				sz := t.Size
				if sz > 1024 {
					sz = 1024
				}
				fg.opt.Reset(e.Buf[off:off+sz], t.isStr, int(9+e.Depth))
				fg.opt.dumpDataByBTF(t.Name, t.Typ, 0, int(t.BitOff), int(t.BitSize))
				fg.buf.WriteString(fg.opt.String())
				fg.buf.WriteString("\n")
			}

		}
	}
	fg.buf.WriteByte('\n')
}

func (fg *FuncGraph) ShowFuncPara(e *FuncEvent) {

	if e.Id == 0 {
		fmt.Fprintf(fg.buf, "%#x %#x %#x", e.Para[0], e.Para[1], e.Para[2])
		return
	}

	funcInfo := fg.idToFuncs[btf.TypeID(e.Id)]
	bFunc := funcInfo.btfinfo
	bFuncProto := bFunc.Type.(*btf.FuncProto)
	var n [1024]byte

	for i, p := range bFuncProto.Params {
		if i >= 5 {
			break
		}
		if i != 0 {
			fg.buf.WriteByte(' ')
		}
		typ := btf.UnderlyingType(p.Type)
		switch t := typ.(type) {
		case *btf.Pointer:
			fg.buf.WriteString(p.Name)
			fg.buf.WriteString("=0x")
			b := n[:0]
			b = strconv.AppendUint(b, e.Para[i], 16)
			fg.buf.Write(b)
			// fmt.Fprintf(s, "%s=%#x", p.Name, e.Para[i])
		case *btf.Int:
			b := n[:0]
			switch {
			case t.Encoding == btf.Signed && t.Size == 4:
				b = strconv.AppendInt(b, int64(int32(e.Para[i])), 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, int32(e.Para[i]))
			case t.Encoding == btf.Signed && t.Size == 8:
				b = strconv.AppendInt(b, int64(e.Para[i]), 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, int64(e.Para[i]))
			case t.Encoding == btf.Unsigned && t.Size == 4:
				b = strconv.AppendUint(b, uint64(uint32(e.Para[i])), 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, uint32(e.Para[i]))
			case t.Encoding == btf.Unsigned && t.Size == 8:
				b = strconv.AppendUint(b, uint64((e.Para[i])), 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, uint64(e.Para[i]))
			case t.Encoding == btf.Char:
				b = strconv.AppendUint(b, uint64(byte(e.Para[i])), 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, byte(e.Para[i]))
			case t.Encoding == btf.Bool:
				if e.Para[i] != 0 {
					b = append(b, "true"...)
				} else {
					b = append(b, "false"...)
				}
				// fmt.Fprintf(s, "%s=%v", p.Name, e.Para[i] != 0)
			default:
				b = strconv.AppendUint(b, e.Para[i], 10)
				// fmt.Fprintf(s, "%s=%v", p.Name, e.Para[i])
			}
			fg.buf.WriteString(p.Name)
			fg.buf.WriteString("=")
			fg.buf.Write(b)
		default:
			fg.buf.WriteString(p.Name)
			fg.buf.WriteString("=")
			b := n[:0]
			b = strconv.AppendUint(b, e.Para[i], 10)
			fg.buf.Write(b)
			// fmt.Fprintf(s, "%s=%v", p.Name, e.Para[i])
		}
	}

}

func (fg *FuncGraph) ShowFuncRet(e *FuncEvent) {
	if e.Id == 0 {
		fmt.Fprintf(fg.buf, "%#x", e.Ret)
		return
	}
	fg.buf.WriteString("ret=")
	funcInfo := fg.idToFuncs[btf.TypeID(e.Id)]
	bFunc := funcInfo.btfinfo
	bFuncProto := bFunc.Type.(*btf.FuncProto)
	typ := btf.UnderlyingType(bFuncProto.Return)
	switch t := typ.(type) {
	case *btf.Int:
		switch {
		case t.Encoding == btf.Signed && t.Size == 4:
			fmt.Fprintf(fg.buf, "%v", int32(e.Ret))
		case t.Encoding == btf.Signed && t.Size == 8:
			fmt.Fprintf(fg.buf, "%v", int64(e.Ret))
		case t.Encoding == btf.Unsigned && t.Size == 4:
			fmt.Fprintf(fg.buf, "%v", uint32(e.Ret))
		case t.Encoding == btf.Unsigned && t.Size == 8:
			fmt.Fprintf(fg.buf, "%v", uint64(e.Ret))
		case t.Encoding == btf.Char:
			fmt.Fprintf(fg.buf, "%v", byte(e.Ret))
		case t.Encoding == btf.Bool:
			fmt.Fprintf(fg.buf, "%v", e.Ret != 0)
		default:
			fmt.Fprintf(fg.buf, "%d", e.Ret)
		}
	case *btf.Pointer:
		fmt.Fprintf(fg.buf, "%#x", e.Ret)
	case *btf.Void:
		fg.buf.WriteString("void")
	default:
		fmt.Fprintf(fg.buf, "%v", e.Ret)
	}

}

func main() {
	cli.AppHelpTemplate = fmt.Sprintf(`%s
EXAMPLES:
	./efunc info "ip_rcv"
	./efunc info "ip_rcv(*skb, skb->len, skb->dev.name)"
	./efunc trace -e ".ip_rcv(skb->len)" -a ":net/ipv4/*" -a "virtio_net:*"	

ENVIRONMENT:
	BTF_SHOW_ZERO		[default: 0] show field info even value is zero
	`, cli.AppHelpTemplate)
	app := &cli.App{
		Usage:   "A eBPF-based trace tool like ftrace funcgraph",
		Version: "0.0.2",
		Commands: []*cli.Command{
			{
				Name:  "info",
				Usage: "parse func expr and generate trace data",
				Action: func(cCtx *cli.Context) error {
					fn := cCtx.Args().First()
					expr, err := ParseFuncWithPara(fn)
					if err != nil {
						return fmt.Errorf("parsing %q\n%w", fn, err)
					}
					fmt.Printf("parsing %s\n", fn)
					fmt.Printf("expr: %+v\n\n", expr)

					spec, err := loadbtfSpec(expr.Module)
					if err != nil {
						return err
					}

					typ, err := spec.AnyTypeByName(expr.Name)
					if err != nil {
						return err
					}
					if btfData, ok := typ.(*btf.Func); ok {
						s := showBtfFunc(btfData)
						fmt.Printf("%s\n\n", s)
						for _, data := range expr.Datas {
							genTraceData(data, btfData)
						}
					} else {
						return fmt.Errorf("expect function but got %+v", typ)
					}

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
						Name:  "max-entries",
						Value: 16777216,
						Usage: "`SIZE` of ringbuffer in bytes",
						Action: func(ctx *cli.Context, u uint) error {
							if u&(u-1) != 0 {
								return fmt.Errorf("max-entries must be pow of 2: %d", u)
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
				},
				Action: func(ctx *cli.Context) error {
					exprFmt, _ := regexp.Compile(`.*\(.*\)`)
					entryFuncs := []string{}
					entryFuncExprs := []*FuncExpr{}
					entryFuncsOfDwarf := map[Symbol]struct{}{}
					for _, e := range ctx.StringSlice("entry") {
						if exprFmt.MatchString(e) {
							if fe, err := ParseFuncWithPara(e); err == nil {
								entryFuncExprs = append(entryFuncExprs, fe)
							} else {
								return fmt.Errorf("parsing %s\n%w", e, err)
							}
						} else if e[0] == ':' {
							maps.Copy(entryFuncsOfDwarf, funcsFromFile(e[1:]))
						} else {
							entryFuncs = append(entryFuncs, e)
						}
					}

					allowFuncs := []string{}
					allowFuncExprs := []*FuncExpr{}
					allowFuncsOfDwarf := map[Symbol]struct{}{}
					for _, a := range ctx.StringSlice("allow") {
						if exprFmt.MatchString(a) {
							if fe, err := ParseFuncWithPara(a); err == nil {
								allowFuncExprs = append(allowFuncExprs, fe)
							} else {
								return fmt.Errorf("parsing %s\n%w", a, err)
							}
						} else if a[0] == ':' {
							maps.Copy(allowFuncsOfDwarf, funcsFromFile(a[1:]))
						} else {
							allowFuncs = append(allowFuncs, a)
						}
					}

					opt := Option{
						entryFuncs:        entryFuncs,
						allowFuncs:        allowFuncs,
						denyFuncs:         ctx.StringSlice("deny"),
						entryFuncExprs:    entryFuncExprs,
						allowFuncExprs:    allowFuncExprs,
						entryFuncsOfDwarf: entryFuncsOfDwarf,
						allowFuncsOfDwarf: allowFuncsOfDwarf,
						allowPids:         ctx.IntSlice("pid"),
						denyPids:          ctx.IntSlice("no-pid"),
						allowComms:        ctx.StringSlice("comm"),
						denyComms:         ctx.StringSlice("no-comm"),
						verbose:           ctx.Bool("verbose"),
						bpfLog:            ctx.Bool("bpf-log"),
						dryRun:            ctx.Bool("dry-run"),
						maxEntries:        uint32(ctx.Uint("max-entries")),
						mode:              ctx.String("mode"),
					}

					fg, err := NewFuncGraph(opt)
					if err != nil {
						return err
					}
					if err := fg.init(); err != nil {
						return err
					}
					if err := fg.run(); err != nil {
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
