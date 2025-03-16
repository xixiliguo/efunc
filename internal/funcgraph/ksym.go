package funcgraph

import (
	"bufio"
	"bytes"
	"errors"
	"iter"
	"os"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Symbol struct {
	Addr   uint64
	Name   string
	Module string
	isDup  bool
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

func availKprobeSymbols() map[Symbol]struct{} {

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
		b := bytes.Fields(scanner.Bytes())
		if bytes.HasPrefix(b[0], []byte("__ftrace_invalid_address___")) {
			continue
		}
		m := ""
		if len(b) == 2 {
			m = string(bytes.Trim(b[1], "[]"))
		}
		symbol := Symbol{
			Name:   string(b[0]),
			Module: m,
		}
		syms[symbol] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return syms
	}
	return syms
}

var getKallSyms = sync.OnceValues(func() ([]Symbol, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return []Symbol{}, err
	}
	defer f.Close()

	syms := []Symbol{}
	idx := 0

	type cmp struct {
		name   string
		module string
	}
	dup := make(map[cmp][]int)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bs := bytes.Fields(scanner.Bytes())
		if bs[1][0] != 't' && bs[1][0] != 'T' {
			continue
		}

		addr := convertAddr(bs[0])
		name := string(bs[2])
		m := ""
		if len(bs) == 4 {
			m = string(bytes.Trim(bs[3], "[]"))
		}

		sym := Symbol{
			Addr:   addr,
			Name:   name,
			Module: m,
		}

		syms = append(syms, sym)
		c := cmp{
			name:   sym.Name,
			module: sym.Module,
		}
		dup[c] = append(dup[c], idx)
		idx++
	}
	if err := scanner.Err(); err != nil {
		return syms, err
	}

	for _, idxs := range dup {
		if len(idxs) > 1 {
			for i := range idxs {
				syms[i].isDup = true
			}
		}
	}

	sort.Slice(syms, func(i, j int) bool {
		return syms[i].Addr < syms[j].Addr
	})
	return syms, err
})

var symCache = map[uint64]Symbol{}

func SymbolByAddr(addr uint64) (Symbol, error) {

	if s, ok := symCache[addr]; ok {
		return s, nil
	}
	syms, err := getKallSyms()
	if err != nil {
		return Symbol{}, err
	}
	idx := sort.Search(len(syms), func(i int) bool {
		return syms[i].Addr >= addr
	})

	if idx < len(syms) && syms[idx].Addr == addr {
		symCache[addr] = syms[idx]
		return symCache[addr], nil
	}
	if idx == 0 {
		return Symbol{}, errors.New("no found sym")
	}
	symCache[addr] = syms[idx-1]
	return symCache[addr], nil
}

func AllKSyms() iter.Seq[Symbol] {
	return func(yield func(Symbol) bool) {
		if syms, err := getKallSyms(); err == nil {
			for _, sym := range syms {
				if sym.isDup {
					continue
				}
				if !yield(sym) {
					return
				}
			}
		}
	}
}

func convertAddr(b []byte) uint64 {
	v := uint64(0)
	for _, c := range b {
		delta := c - '0'
		if c >= 'a' && c <= 'f' {
			delta = c - 'a' + 10
		}
		if c >= 'A' && c <= 'F' {
			delta = c - 'A' + 10
		}
		v = (v << 4) + uint64(delta)
	}
	return v
}
