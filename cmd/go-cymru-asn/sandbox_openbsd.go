//go:build openbsd

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func sandbox() {
	if err := unix.Pledge("stdio dns inet", ""); err != nil {
		fmt.Fprintf(os.Stderr, "pledge: %v\n", err)
		os.Exit(1)
	}
}
