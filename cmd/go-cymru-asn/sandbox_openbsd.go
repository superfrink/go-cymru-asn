//go:build openbsd

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func sandbox() {
	unveilPaths := []struct {
		path  string
		perms string
	}{
		{"/etc/resolv.conf", "r"},
		{"/etc/ssl/cert.pem", "r"},
		{"/etc/ssl/certs", "r"},
	}

	for _, u := range unveilPaths {
		if err := unix.Unveil(u.path, u.perms); err != nil {
			fmt.Fprintf(os.Stderr, "unveil %s: %v\n", u.path, err)
			os.Exit(1)
		}
	}

	if err := unix.UnveilBlock(); err != nil {
		fmt.Fprintf(os.Stderr, "unveil block: %v\n", err)
		os.Exit(1)
	}

	if err := unix.Pledge("stdio dns inet", ""); err != nil {
		fmt.Fprintf(os.Stderr, "pledge: %v\n", err)
		os.Exit(1)
	}
}
