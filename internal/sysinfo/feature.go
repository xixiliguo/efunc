package sysinfo

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate bpf2go -cc clang -cflags $BPF_CFLAGS -target amd64,arm64 fake nanosleep.bpf.c -- -I../include

func DetectRetOffset() (uint64, error) {
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

func HaveKprobeMulti() bool {

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
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{
		Symbols: []string{"vprintk"},
	}

	kp, err := link.KprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer kp.Close()
	return true
}

func HaveGetFuncIP() bool {
	err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnGetFuncIp)
	return err == nil
}

func HaveRingBuf() bool {
	err := features.HaveMapType(ebpf.RingBuf)
	return err == nil
}

func HaveBTF() bool {
	h, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.IsVmlinux()
	})
	return err == nil && h != nil
}
func HaveBTFModule() bool {
	h, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.IsModule()
	})
	return err == nil && h != nil
}

func ShowSysInfo() (string, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 4096))

	uts := unix.Utsname{}
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}

	buf.WriteString("System\n")
	fmt.Fprintf(buf, "  OS: %s %s %s\n", unix.ByteSliceToString(uts.Sysname[:]),
		unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Version[:]))
	fmt.Fprintf(buf, "  Arch: %s\n", unix.ByteSliceToString(uts.Machine[:]))
	fmt.Fprintf(buf, "  Go: %s\n", runtime.Version())
	buf.WriteString("\n")

	buf.WriteString("eBPF feature\n")
	fmt.Fprintf(buf, "  btf: %t\n", HaveBTF())
	fmt.Fprintf(buf, "  btf module: %t\n", HaveBTFModule())
	fmt.Fprintf(buf, "  ringbuf map: %t\n", HaveRingBuf())
	fmt.Fprintf(buf, "  kprobeMulti: %t\n", HaveKprobeMulti())
	fmt.Fprintf(buf, "  get_func_ip: %t\n", HaveGetFuncIP())

	if offset, err := DetectRetOffset(); err != nil {
		return "", err
	} else {
		fmt.Fprintf(buf, "  retOffset: %d\n", offset)
	}

	return buf.String(), nil
}
