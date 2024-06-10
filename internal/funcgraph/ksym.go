package funcgraph

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
		return syms
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
		return syms
	}
	return syms
})

type KSymCache struct {
	syms  []Symbol
	cache map[uint64]Symbol
	dups  map[string]int
}

func NewKSymCache() (*KSymCache, error) {
	k := &KSymCache{
		syms:  []Symbol{},
		cache: make(map[uint64]Symbol),
		dups:  make(map[string]int),
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

func (k *KSymCache) SymbolByAddr(addr uint64) Symbol {

	if s, ok := k.cache[addr]; ok {
		return s
	}

	idx := sort.Search(len(k.syms), func(i int) bool {
		return k.syms[i].Addr >= addr
	})
	if idx == 0 {
		k.cache[addr] = Symbol{}
		return k.cache[addr]
	}
	if idx < len(k.syms) && k.syms[idx].Addr == addr {
		k.cache[addr] = k.syms[idx]
		return k.cache[addr]
	}
	k.cache[addr] = k.syms[idx-1]
	return k.cache[addr]
}

func (k *KSymCache) Iterate() *SymsIterator {
	return &SymsIterator{k: k}
}

type SymsIterator struct {
	k     *KSymCache
	index int
	Symbol
}

func (iter *SymsIterator) Next() bool {
	for iter.index < len(iter.k.syms) {
		sym := iter.k.syms[iter.index]
		if iter.k.dups[sym.Module+sym.Name] <= 1 {
			break
		} else {
			iter.index++
		}
	}

	if iter.index >= len(iter.k.syms) {
		return false
	}
	iter.Symbol = iter.k.syms[iter.index]
	iter.index++
	return true
}
