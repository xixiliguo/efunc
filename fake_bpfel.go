// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadFake returns the embedded CollectionSpec for fake.
func loadFake() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FakeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load fake: %w", err)
	}

	return spec, err
}

// loadFakeObjects loads fake and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*fakeObjects
//	*fakePrograms
//	*fakeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFakeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFake()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// fakeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fakeSpecs struct {
	fakeProgramSpecs
	fakeMapSpecs
}

// fakeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fakeProgramSpecs struct {
	Funcentry *ebpf.ProgramSpec `ebpf:"funcentry"`
	Funcret   *ebpf.ProgramSpec `ebpf:"funcret"`
}

// fakeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fakeMapSpecs struct {
	RetOffset *ebpf.MapSpec `ebpf:"ret_offset"`
}

// fakeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type fakeObjects struct {
	fakePrograms
	fakeMaps
}

func (o *fakeObjects) Close() error {
	return _FakeClose(
		&o.fakePrograms,
		&o.fakeMaps,
	)
}

// fakeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type fakeMaps struct {
	RetOffset *ebpf.Map `ebpf:"ret_offset"`
}

func (m *fakeMaps) Close() error {
	return _FakeClose(
		m.RetOffset,
	)
}

// fakePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type fakePrograms struct {
	Funcentry *ebpf.Program `ebpf:"funcentry"`
	Funcret   *ebpf.Program `ebpf:"funcret"`
}

func (p *fakePrograms) Close() error {
	return _FakeClose(
		p.Funcentry,
		p.Funcret,
	)
}

func _FakeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed fake_bpfel.o
var _FakeBytes []byte
