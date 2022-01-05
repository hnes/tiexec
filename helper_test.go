package main

import (
	"fmt"
	"testing"
)

func Test_parseProcMapsFile(t *testing.T) {
	lists := parseProcMapsFile("/proc/self/maps")
	for _, v := range lists {
		fmt.Printf("%x-%x %x |%s| |%s|\n", v.StartAddr, v.EndAddr, v.Size, v.PermStr, v.PathName)
	}
}
