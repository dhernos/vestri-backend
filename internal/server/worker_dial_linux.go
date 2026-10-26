//go:build linux

package server

import (
	"syscall"
)

func setTCPMaxSegment(network, address string, conn syscall.RawConn, mss int) error {
	var sockErr error
	if err := conn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
	}); err != nil {
		return err
	}
	return sockErr
}
