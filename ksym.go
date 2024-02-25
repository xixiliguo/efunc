package main

import (
	"bufio"
	"bytes"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

func fsType(path string) (int64, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return 0, err
	}

	fsType := int64(statfs.Type)
	if unsafe.Sizeof(statfs.Type) == 4 {
		// We're on a 32 bit arch, where statfs.Type is int32. bpfFSType is a
		// negative number when interpreted as int32 so we need to cast via
		// uint32 to avoid sign extension.
		fsType = int64(uint32(statfs.Type))
	}
	return fsType, nil
}

var availKprobeSymbol = sync.OnceValue[map[Symbol]struct{}](func() map[Symbol]struct{} {

	var path string
	for _, p := range []struct {
		path   string
		fsType int64
	}{
		{"/sys/kernel/tracing", unix.TRACEFS_MAGIC},
		{"/sys/kernel/debug/tracing", unix.TRACEFS_MAGIC},
		{"/sys/kernel/debug/tracing", unix.DEBUGFS_MAGIC},
	} {
		if fsType, err := fsType(p.path); err == nil && fsType == p.fsType {
			path = p.path
			break
		}
	}

	syms := make(map[Symbol]struct{})
	b, err := os.ReadFile(path + "/available_filter_functions")
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(b))
	for scanner.Scan() {
		s := strings.Fields(scanner.Text())
		if strings.HasPrefix(s[0], "__ftrace_invalid_address___") {
			continue
		}
		m := ""
		if len(s) == 2 {
			m = strings.Trim(s[1], "[]")
		}
		symbol := Symbol{
			Name:   s[0],
			Module: m,
		}
		syms[symbol] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return syms
})

func isAvailKprobeSymbol(s Symbol) bool {
	syms := availKprobeSymbol()
	_, ok := syms[Symbol{
		Name:   s.Name,
		Module: s.Module,
	}]
	return ok
}

type SymbolType int

const (
	FuncType SymbolType = iota
	NonFuncType
)

type Symbol struct {
	Addr   uint64
	Type   SymbolType
	Name   string
	Module string
}

type KSymCache struct {
	syms        []Symbol
	addrToSym   map[uint64]Symbol
	resultCache map[uint64]Symbol
	dups        map[string]int
}

func NewKSymCache() (KSymCache, error) {
	k := KSymCache{
		syms:        []Symbol{},
		addrToSym:   make(map[uint64]Symbol),
		resultCache: make(map[uint64]Symbol),
		dups:        make(map[string]int),
	}
	b, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return k, err
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(b))
	for scanner.Scan() {
		s := strings.Fields(scanner.Text())

		addr, err := strconv.ParseUint(s[0], 16, 64)
		if err != nil {
			return k, err
		}
		t := FuncType
		if s[1] != "t" && s[1] != "T" {
			t = NonFuncType
		}
		m := ""
		if len(s) == 4 {
			m = strings.Trim(s[3], "[]")
		}
		sym := Symbol{
			Addr:   addr,
			Type:   t,
			Name:   s[2],
			Module: m,
		}
		k.syms = append(k.syms, sym)
		if _, ok := k.addrToSym[sym.Addr]; !ok {
			k.addrToSym[sym.Addr] = sym
		}
		k.dups[sym.Module+sym.Name]++
	}
	if err := scanner.Err(); err != nil {
		return k, err
	}
	sort.Slice(k.syms, func(i, j int) bool {
		return k.syms[i].Addr < k.syms[j].Addr
	})

	return k, nil
}

func (k KSymCache) SymbolByAddr(addr uint64, mustMatch bool) Symbol {

	if mustMatch {
		return k.addrToSym[addr]
	}

	if s, ok := k.resultCache[addr]; ok {
		return s
	}

	idx := sort.Search(len(k.syms), func(i int) bool {
		return k.syms[i].Addr > addr
	})
	if idx == 0 {
		k.resultCache[addr] = Symbol{}
		return Symbol{}
	}
	k.resultCache[addr] = k.syms[idx-1]
	return k.syms[idx-1]
}

func (k KSymCache) Iterate() *SymsIterator {
	return &SymsIterator{syms: k.syms, dups: k.dups}
}

type SymsIterator struct {
	Symbol
	syms  []Symbol
	dups  map[string]int
	index int
}

func (iter *SymsIterator) Next() bool {
	for iter.index < len(iter.syms) {
		sym := iter.syms[iter.index]
		if iter.dups[sym.Module+sym.Name] <= 1 {
			break
		} else {
			iter.index++
		}
	}

	if len(iter.syms) <= iter.index {
		return false
	}
	iter.Symbol = iter.syms[iter.index]
	iter.index++
	return true
}
