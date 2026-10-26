//go:build !linux

package server

import "syscall"

func setTCPMaxSegment(network, address string, conn syscall.RawConn, mss int) error {
	return nil
}
