//go:build ignore

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: generate-bpf <output-dir>")
		os.Exit(1)
	}

	outputDir := os.Args[1]

	fmt.Printf("Generating BPF files to %s\n", outputDir)
}