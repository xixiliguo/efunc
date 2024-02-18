package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"path"
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

func funcsFromFile(pattern string) map[Symbol]struct{} {
	funcs := make(map[Symbol]struct{})
	data := dwarfData()
	if data == nil {
		return funcs
	}

	r := data.Reader()
	var currIdx int
	// var currName string
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
			lr, _ := data.LineReader(cu)
			if match, _ := path.Match(pattern, name); match {
				for idx, f := range lr.Files() {
					if f != nil {
						if f.Name == name {
							// currName = name
							currIdx = idx
						}
					}
				}
				// currCu = cu
			} else {
				// currCu = nil
				r.SkipChildren()
			}
		}
		if cu.Tag == dwarf.TagSubprogram && cu.Children {
			if v, ok := cu.Val(dwarf.AttrDeclFile).(int64); ok {
				if v == int64(currIdx) {
					funcName, _ := cu.Val(dwarf.AttrName).(string)
					// fmt.Printf("file: %s\n", currName)
					// fmt.Printf("prog: %s\n", funcName)
					// fmt.Printf("prog: %+v\n", cu)
					s := Symbol{
						Name:   funcName,
						Addr:   0,
						Module: "",
					}
					funcs[s] = struct{}{}
				}
			}
		}
	}
	// fmt.Println(funcs)
	return funcs
}
