package funcgraph

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

func findVMLinux() (string, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname failed: %w", err)
	}

	release := unix.ByteSliceToString(uname.Release[:])

	locations := []string{
		"/usr/lib/debug/lib/modules/%s/vmlinux",
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
	}

	for _, loc := range locations {
		path := fmt.Sprintf(loc, release)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("no vmlinux file found for kernel version %s", release)
}

var dwarfData = sync.OnceValue[*dwarf.Data](func() *dwarf.Data {
	path, err := findVMLinux()
	if err != nil {
		return nil
	}
	eFile, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer eFile.Close()
	dwarfData, err := eFile.DWARF()
	if err != nil {
		return nil
	}
	return dwarfData
})

func FuncsFromFile(pattern string) map[Symbol]struct{} {
	funcs := make(map[Symbol]struct{})
	data := dwarfData()
	if data == nil {
		return funcs
	}

	r := data.Reader()
	for {
		cu, err := r.Next()
		if err != nil {
			break
		}
		if cu == nil {
			break
		}

		if cu.Tag == dwarf.TagCompileUnit {
			name := cu.Val(dwarf.AttrName).(string)
			if filepath.IsAbs(name) {
				if idx := strings.Index(name, getOSReleaseSep()); idx != -1 {
					name = name[idx+len(getOSReleaseSep()):]
				}
			}
			if match, _ := path.Match(pattern, name); match {
				lr, _ := data.LineReader(cu)
				currIdx := 1
				for idx, f := range lr.Files() {
					if f != nil {
						if f.Name == name {
							currIdx = idx
							break
						}
					}
				}

				for {
					e, err := r.Next()
					if err != nil || e == nil || e.Tag == 0 {
						break
					}
					if e.Tag == dwarf.TagSubprogram {
						if v, ok := e.Val(dwarf.AttrDeclFile).(int64); ok {
							if v == int64(currIdx) {
								funcName, _ := e.Val(dwarf.AttrName).(string)
								// fmt.Printf("file: %s\n", currName)
								// fmt.Printf("prog: %s\n", funcName)
								// fmt.Printf("prog: %+v\n", cu)
								s := Symbol{
									Name:   funcName,
									Module: "",
								}
								funcs[s] = struct{}{}
							}
						}
					}
					if e.Children {
						r.SkipChildren()
					}
				}
			}
			r.SkipChildren()
		}

	}
	return funcs
}
