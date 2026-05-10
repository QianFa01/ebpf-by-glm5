//go:build linux

package bpf

import "embed"

//go:embed bpf_*.o
var bpfObjects embed.FS

func loadBpfSpecs() (*ebpf.CollectionSpec, error) {
	file, err := bpfObjects.Open("bpf_process.o")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	spec, err := ebpf.LoadCollectionSpecFromReader(file)
	if err != nil {
		return nil, err
	}
	
	return spec, nil
}