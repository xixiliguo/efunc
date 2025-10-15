package funcgraph

import (
	"bufio"
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unique"
	"unsafe"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/reader"
	"golang.org/x/sys/unix"
)

var ErrNotFoundKsym = errors.New("no found sym")
var ErrNotFoundMod = errors.New("no found module")

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

type KprobeSymbol struct {
	Module string
	Name   string
}

func availKprobeSymbols() map[KprobeSymbol]struct{} {
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

	syms := make(map[KprobeSymbol]struct{})
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
		symbol := KprobeSymbol{
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

var getOSReleaseSep = sync.OnceValue(func() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return ""
	}

	release := unix.ByteSliceToString(uname.Release[:])
	return release + "/"
})

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

type Symbol struct {
	Name   string
	Module string
}

type FileLine struct {
	file string
	line int
}

type InlinedFn struct {
	Name string
	FileLine
}

type KernelSymbol struct {
	Name   string
	Module string
	Addr   uint64
	Offset uint64
	IsDup  bool
	FileLine
	Inlined []InlinedFn
}

type rangeOffset struct {
	low    uint64
	high   uint64
	offset dwarf.Offset
}

type lineEntry struct {
	addr uint64
	file unique.Handle[string]
	line int
}

type DebugInfo struct {
	moduleName       string
	data             *dwarf.Data
	offset           uint64
	ranges           []rangeOffset
	subPrograms      map[dwarf.Offset][]*godwarf.Tree
	abstractPrograms map[dwarf.Offset]string
	lineEntries      map[dwarf.Offset][]lineEntry
	lineFiles        map[dwarf.Offset][]string
}

func newDebugInfo(modName string, data *dwarf.Data, offset uint64) (*DebugInfo, error) {

	d := &DebugInfo{
		moduleName:       modName,
		offset:           offset,
		ranges:           make([]rangeOffset, 0, 4096),
		subPrograms:      make(map[dwarf.Offset][]*godwarf.Tree),
		abstractPrograms: make(map[dwarf.Offset]string),
		lineEntries:      make(map[dwarf.Offset][]lineEntry),
		lineFiles:        make(map[dwarf.Offset][]string),
	}

	rOffset := []rangeOffset{}

	r := data.Reader()
	for {
		cu, err := r.Next()
		if err != nil {
			return nil, err
		}
		if cu == nil {
			break
		}
		if cu.Tag == dwarf.TagCompileUnit {
			rs, err := data.Ranges(cu)
			if err != nil {
				return nil, err
			}
			for _, r := range rs {
				rOffset = append(rOffset, rangeOffset{
					low:    r[0],
					high:   r[1],
					offset: cu.Offset,
				})
			}
		}
		if cu.Children {
			r.SkipChildren()
		}
	}
	sort.Slice(rOffset, func(i, j int) bool {
		return rOffset[i].low >= rOffset[j].low
	})

	d.data = data
	d.ranges = rOffset
	return d, nil
}

func (d *DebugInfo) FrameByAddr(addr uint64, ksym *KernelSymbol) error {

	realAddr := addr - d.offset

	idx := sort.Search(len(d.ranges), func(i int) bool {
		return realAddr >= d.ranges[i].low
	})
	if idx >= len(d.ranges) {
		return fmt.Errorf("no found symbof for %x", addr)
	}

	cuOffset := d.ranges[idx].offset
	if err := d.parseCompileUnit(cuOffset); err != nil {
		return err
	}

	// frames := make([]Frame, 0, 1)
	var root *godwarf.Tree
	name := ""
	funcOffset := uint64(0)
	for _, tr := range d.subPrograms[cuOffset] {
		for _, rng := range tr.Ranges {
			if rng[0] <= realAddr && realAddr < rng[1] {
				name, _ = tr.Val(dwarf.AttrName).(string)
				funcOffset = realAddr - rng[0]
				root = tr
				break
			}
		}
	}

	lines := d.lineEntries[cuOffset]

	idx = sort.Search(len(lines), func(i int) bool {
		return realAddr >= lines[i].addr
	})
	if idx >= len(lines) {
		return fmt.Errorf("no found symbof for %x", addr)
	}

	nextFileName := lines[idx].file.Value()
	nextLineNo := lines[idx].line

	if root == nil {
		ksym.Module = d.moduleName
		ksym.file = nextFileName
		ksym.line = nextLineNo
		return nil
	}

	// if addr == 0xffffffff81aed903 {
	// 	for _, l := range lines {
	// 		fmt.Printf("aaa %x %+v\n", l.Address, l)
	// 	}
	// 	fmt.Printf("aaa %s %s %d\n", d.moduleName, lines[idx].File.Name, lines[idx].Line)
	// }

	for _, tr := range reader.InlineStack(root, realAddr) {
		offset := tr.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset)
		originName := d.abstractPrograms[offset]
		fileIdx := tr.Val(dwarf.AttrCallFile).(int64)
		lineNo := tr.Val(dwarf.AttrCallLine).(int64)
		// inlineFrame := Frame{module: d.moduleName}
		// inlineFrame.funeName = originName
		// inlineFrame.inline = true
		// inlineFrame.file = nextFileName
		// inlineFrame.lineno = nextLineNo
		ksym.Inlined = append(ksym.Inlined, InlinedFn{
			Name: originName,
			FileLine: FileLine{
				file: nextFileName,
				line: nextLineNo,
			},
		})
		nextFileName = d.lineFiles[cuOffset][fileIdx]
		nextLineNo = int(lineNo)
	}
	ksym.Module = d.moduleName
	ksym.Name = name
	ksym.Offset = funcOffset
	ksym.file = nextFileName
	ksym.line = nextLineNo
	// frames = append(frames, Frame{
	// 	module:   d.moduleName,
	// 	funeName: name,
	// 	offset:   funcOffset,
	// 	file:     nextFileName,
	// 	lineno:   nextLineNo,
	// })
	return nil
}

func (d *DebugInfo) parseCompileUnit(offset dwarf.Offset) error {

	if _, ok := d.lineEntries[offset]; ok {
		return nil
	}

	r := d.data.Reader()
	r.Seek(offset)
	cu, err := r.Next()
	if err != nil {
		return err
	}
	if cu.Tag != dwarf.TagCompileUnit {
		return fmt.Errorf("wrong enttry, expect compile uint: %+v", cu)
	}
	compileDir := cu.Val(dwarf.AttrCompDir).(string)

	lr, err := d.data.LineReader(cu)
	if err != nil {
		return err
	}

	files := lr.Files()
	lineFiles := make([]string, len(files))
	for i, f := range files {
		if i == 0 {
			continue
		}
		lineFiles[i] = f.Name
		// if p, err := filepath.Rel(compileDir, f.Name); err == nil {
		// 	lineFiles[i] = p
		// }
		if filepath.IsAbs(f.Name) {
			if idx := strings.Index(f.Name, getOSReleaseSep()); idx != -1 {
				lineFiles[i] = f.Name[idx+len(getOSReleaseSep()):]
			}
		}
	}
	d.lineFiles[cu.Offset] = lineFiles

	lines := []lineEntry{}
	for {
		le := dwarf.LineEntry{}
		err := lr.Next(&le)
		if err != nil {
			break
		}
		line := lineEntry{
			addr: le.Address,
			line: le.Line,
		}
		fileName := le.File.Name
		if p, err := filepath.Rel(compileDir, fileName); err == nil {
			fileName = p
		}
		line.file = unique.Make(fileName)
		lines = append(lines, line)
	}
	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i].addr >= lines[j].addr
	})
	d.lineEntries[cu.Offset] = lines

	for {
		ent, err := r.Next()
		if err != nil {
			return err
		}
		if ent == nil {
			break
		}
		if ent.Tag == 0 {
			break
		}
		if ent.Tag == dwarf.TagSubprogram {
			inl := ent.AttrField(dwarf.AttrInline)
			if inl == nil {
				tr, err := godwarf.LoadTree(ent.Offset, d.data, 0)
				if err != nil {
					return err
				}
				d.subPrograms[cu.Offset] = append(d.subPrograms[cu.Offset], tr)
			} else {
				name := ent.Val(dwarf.AttrName).(string)
				d.abstractPrograms[ent.Offset] = name
			}
		}
		if ent.Children {
			r.SkipChildren()
		}
	}
	return nil
}

func findPath(name string) (string, error) {

	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname failed: %w", err)
	}

	release := unix.ByteSliceToString(uname.Release[:])

	locations := []string{
		"/usr/lib/debug/lib/modules/%s",
		"/usr/lib/debug/boot/vmlinux-%s",
	}
	result := ""
	for _, loc := range locations {
		searchPaths := fmt.Sprintf(loc, release)
		filepath.WalkDir(searchPaths, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (d.Name() == name || d.Name() == name+"-"+release || d.Name() == name+".ko" || d.Name() == name+".ko.debug") {
				result = path
				return filepath.SkipAll
			}
			return nil
		})
		if result != "" {
			return result, nil
		}
	}
	return "", fmt.Errorf("no %s debuginfo file for kernel version %s", name, release)
}

type KernelSymbolizer struct {
	modSpaces []moduleAddrSpace
}

type symbol struct {
	addr  uint64
	index uint32
	isDup bool
}

type moduleAddrSpace struct {
	name  string
	start uint64
	end   uint64
	// syms      []KernelSymbol
	tryLoad   bool
	debugInfo *DebugInfo
	names     []byte
	symbols   []symbol
}

var globalKernelSymbolizer *KernelSymbolizer

func NewKsymbolizer() (*KernelSymbolizer, error) {
	if globalKernelSymbolizer != nil {
		return globalKernelSymbolizer, nil
	}

	ksym := &KernelSymbolizer{}
	if err := ksym.loadModuleBase(); err != nil {
		return ksym, err
	}

	if err := ksym.loadKernelSymbol(); err != nil {
		return ksym, err
	}

	m, _ := ksym.ModuleByName("vmlinux")
	ksym.tryLoadDebugInfo(m)
	globalKernelSymbolizer = ksym
	return globalKernelSymbolizer, nil
}

func (k *KernelSymbolizer) tryLoadDebugInfo(m *moduleAddrSpace) {
	if m.tryLoad {
		return
	}
	m.tryLoad = true
	if file, err := findPath(m.name); err == nil {
		if e, err := elf.Open(file); err == nil {
			baseAddr := uint64(0)
			for _, s := range e.Sections {
				if s.Name == ".text" {
					baseAddr = s.Addr
					break
				}
			}
			offset := m.start - baseAddr
			if d, err := e.DWARF(); err == nil {
				if debug, err := newDebugInfo(m.name, d, offset); err == nil {
					m.debugInfo = debug
				}
			}
		}

	}
}

func (k *KernelSymbolizer) loadKernelSymbol() error {

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer f.Close()

	curr, err := k.ModuleByName("vmlinux")
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bs := bytes.Fields(scanner.Bytes())
		if bs[1][0] != 't' && bs[1][0] != 'T' {
			continue
		}

		addr := convertAddr(bs[0])
		name := string(bs[2])
		m := "vmlinux"
		if len(bs) == 4 {
			m = string(bytes.Trim(bs[3], "[]"))
		}
		if curr.name != m {
			if mod, err := k.ModuleByName(m); err == nil {
				curr = mod
			} else {
				continue
			}
		}

		sym := symbol{
			addr:  addr,
			index: curr.addName(name),
		}

		curr.symbols = append(curr.symbols, sym)

	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for index, m := range k.modSpaces {
		dup := map[string][]int{}
		for i, sym := range m.symbols {
			m.stringAt(sym.index)
			dup[m.stringAt(sym.index)] = append(dup[m.stringAt(sym.index)], i)
		}
		for _, idx := range dup {
			if len(idx) > 1 {
				for _, i := range idx {
					k.modSpaces[index].symbols[i].isDup = true
				}
			}
		}
		sort.Slice(k.modSpaces[index].symbols, func(i, j int) bool {
			return k.modSpaces[index].symbols[i].addr >= k.modSpaces[index].symbols[j].addr
		})
	}
	return nil
}

func (k *KernelSymbolizer) loadModuleBase() error {

	vmlinuxStart := uint64(0)
	vmlinuxEnd := uint64(0)

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bs := bytes.Fields(scanner.Bytes())
		addr, err := strconv.ParseUint(string(bs[0]), 16, 64)
		if err != nil {
			return err
		}
		if string(bs[2]) == "_stext" || string(bs[2]) == "_text" {
			vmlinuxStart = addr
		}
		if string(bs[2]) == "_etext" {
			vmlinuxEnd = addr
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if vmlinuxStart == 0 || vmlinuxEnd == 0 {
		return fmt.Errorf("no found start/end vmlinux addr")
	}
	k.modSpaces = append(k.modSpaces, moduleAddrSpace{
		name:  "vmlinux",
		start: vmlinuxStart,
		end:   vmlinuxEnd,
	})

	f, err = os.Open("/proc/modules")
	if err != nil {
		return err
	}
	defer f.Close()

	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		bs := bytes.Fields(scanner.Bytes())
		name := string(bs[0])
		addr, err := strconv.ParseUint(string(bs[5]), 0, 64)
		if err != nil {
			return err
		}
		size, _ := strconv.ParseUint(string(bs[1]), 10, 64)
		k.modSpaces = append(k.modSpaces, moduleAddrSpace{
			name:  name,
			start: addr,
			end:   addr + size,
		})

	}
	if err := scanner.Err(); err != nil {
		return err
	}
	sort.Slice(k.modSpaces, func(i, j int) bool {
		return k.modSpaces[i].start >= k.modSpaces[j].start
	})

	return nil
}

func (k *KernelSymbolizer) ModuleByName(name string) (*moduleAddrSpace, error) {

	for i, m := range k.modSpaces {
		if m.name == name {
			return &k.modSpaces[i], nil
		}
	}

	return nil, fmt.Errorf("no %s module", name)
}

func (m *moduleAddrSpace) bytesAt(index uint32) []byte {
	i := int(index)
	l := int(m.names[i])
	return m.names[i+1 : i+1+l]
}

// stringAt recovers the string at `index` received from previous `addName` call.
func (m *moduleAddrSpace) stringAt(index uint32) string {
	return toString(m.bytesAt(index))
}

func (m *moduleAddrSpace) addName(name string) uint32 {
	index := len(m.names)
	l := min(len(name), 255)
	m.names = append(m.names, byte(l))
	m.names = append(m.names, unsafe.Slice(unsafe.StringData(name), l)...)
	return uint32(index)
}

func (m *moduleAddrSpace) SymbolByAddr(addr uint64, ksym *KernelSymbol) (err error) {
	idx := sort.Search(len(m.symbols), func(i int) bool {
		return addr >= m.symbols[i].addr
	})

	if idx >= len(m.symbols) {
		return ErrNotFoundKsym
	}

	sym := m.symbols[idx]
	ksym.Module = m.name
	ksym.Name = m.stringAt(sym.index)
	ksym.Addr = sym.addr
	ksym.Offset = addr - sym.addr
	return nil
}

func (m *moduleAddrSpace) FramesByAddr(addr uint64, ksym *KernelSymbol) error {

	if m.debugInfo == nil {
		idx := sort.Search(len(m.symbols), func(i int) bool {
			return addr >= m.symbols[i].addr
		})
		if idx >= len(m.symbols) {
			return ErrNotFoundKsym
		}
		sym := m.symbols[idx]
		ksym.Name = m.stringAt(sym.index)
		ksym.Module = m.name
		ksym.Offset = addr - sym.addr
		return nil
	}
	err := m.debugInfo.FrameByAddr(addr, ksym)
	if err != nil {
		return err
	}
	if ksym.Name == "" && ksym.file != "" {
		idx := sort.Search(len(m.symbols), func(i int) bool {
			return addr >= m.symbols[i].addr
		})
		if idx >= len(m.symbols) {
			return ErrNotFoundKsym
		}
		sym := m.symbols[idx]
		ksym.Name = m.stringAt(sym.index)
		ksym.Offset = addr - sym.addr
	}
	return err
}

func (k *KernelSymbolizer) SymbolByAddr(addr uint64, ksym *KernelSymbol) (err error) {
	mod, err := k.moduleByAddr(addr)
	if err != nil {
		return err
	}
	return mod.SymbolByAddr(addr, ksym)
}

func (k *KernelSymbolizer) SymbolByName(name string) (addr uint64, err error) {
	modName := "vmlinux"
	if idx := strings.Index(name, ":"); idx != -1 {
		modName = name[:idx]
		name = name[idx+1:]
	}
	for _, m := range k.modSpaces {
		if m.name == modName {
			for _, sym := range m.symbols {
				if m.stringAt(sym.index) == name {
					return sym.addr, nil
				}
			}
		}
	}
	return 0, ErrNotFoundKsym
}

func (k *KernelSymbolizer) moduleByAddr(addr uint64) (*moduleAddrSpace, error) {
	if addr == 0xffffffffc04a53c0 {
		for _, m := range k.modSpaces {
			fmt.Printf("%s %x\n", m.name, m.start)
		}
	}

	idx := sort.Search(len(k.modSpaces), func(i int) bool {
		return addr >= k.modSpaces[i].start
	})
	if idx >= len(k.modSpaces) {
		return nil, ErrNotFoundMod
	}
	return &k.modSpaces[idx], nil
}

func (k *KernelSymbolizer) FramesByAddr(addr uint64, ksym *KernelSymbol) error {
	*ksym = KernelSymbol{}
	mod, err := k.moduleByAddr(addr)
	if err != nil {
		return err
	}
	k.tryLoadDebugInfo(mod)
	return mod.FramesByAddr(addr, ksym)
}

type KernelSymbolIterator struct {
	K      *KernelSymbolizer
	modIdx int
	index  int
}

func (iter *KernelSymbolIterator) Next(ksym *KernelSymbol) bool {
	if len(iter.K.modSpaces) == iter.modIdx {
		return false
	}
	mod := iter.K.modSpaces[iter.modIdx]
	for i := iter.index; i < len(mod.symbols); i++ {
		if mod.symbols[i].isDup {
			continue
		}
		sym := mod.symbols[i]
		ksym.Name = mod.stringAt(sym.index)
		ksym.Module = mod.name
		if mod.name == "vmlinux" {
			ksym.Module = ""
		}
		ksym.Addr = sym.addr
		iter.index = i + 1
		return true
	}
	iter.modIdx++
	iter.index = 0
	return iter.Next(ksym)
}
